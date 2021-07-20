/*
 * OptiMin, an optimal fuzzing corpus minimizer.
 *
 * Author: Adrian Herrera
 */

#include <cstdint>
#include <vector>

#include <llvm/ADT/DenseSet.h>
#include <llvm/ADT/DenseMap.h>
#include <llvm/ADT/SmallVector.h>
#include <llvm/ADT/StringExtras.h>
#include <llvm/ADT/StringMap.h>
#include <llvm/Support/Chrono.h>
#include <llvm/Support/FileSystem.h>
#include <llvm/Support/MemoryBuffer.h>
#include <llvm/Support/Path.h>
#include <llvm/Support/Program.h>
#include <llvm/Support/WithColor.h>

#include "EvalMaxSAT.h"
#include "ProgressBar.h"

using namespace llvm;

namespace {

// -------------------------------------------------------------------------- //
// Classes
// -------------------------------------------------------------------------- //

/// Ensure seed weights default to 1
class WeightT {
 public:
  WeightT() : WeightT(1){};
  WeightT(uint32_t V) : Value(V){};

  operator unsigned() const {
    return Value;
  }

 private:
  const unsigned Value;
};

// -------------------------------------------------------------------------- //
// Typedefs
// -------------------------------------------------------------------------- //

/// AFL tuple (edge) ID
using AFLTupleID = uint32_t;

/// Pair of tuple ID and hit count
using AFLTuple = std::pair<AFLTupleID, /* Frequency */ unsigned>;

/// Coverage for a given seed file
using AFLCoverageVector = std::vector<AFLTuple>;

/// Maps seed file paths to a weight
using WeightsMap = StringMap<WeightT>;

/// A seed identifier in the MaxSAT solver
using SeedID = int;

/// Associates seed identifiers to seed files
using MaxSATSeeds =
    SmallVector<std::pair<SeedID, /* Seed file */ std::string>, 0>;

/// Set of literal identifiers
using MaxSATSeedSet = DenseSet<SeedID>;

/// Maps tuple IDs to the literal identifiers that "cover" that tuple
using MaxSATCoverageMap = DenseMap<AFLTupleID, MaxSATSeedSet>;

// -------------------------------------------------------------------------- //
// Global variables
// -------------------------------------------------------------------------- //

static sys::TimePoint<>     StartTime, EndTime;
static std::chrono::seconds Duration;

static char *                    TargetProg;
static SmallVector<StringRef, 8> TargetArgs;
bool                             TargetArgsHasAtAt = false;
static std::string               AFLShowmapPath;

static std::string Timeout = "none";
static std::string MemLimit = "none";

// This is based on the human class count in `count_class_human[256]` in
// `afl-showmap.c`
static constexpr uint32_t MAX_EDGE_FREQ = 8;
}  // anonymous namespace

// -------------------------------------------------------------------------- //
// Helper functions
// -------------------------------------------------------------------------- //

static void GetWeights(const MemoryBuffer &MB, WeightsMap &Weights) {
  SmallVector<StringRef, 0> Lines;
  MB.getBuffer().split(Lines, '\n');

  unsigned Weight = 0;

  for (const auto &Line : Lines) {
    const auto &[Seed, WeightStr] = Line.split(',');

    to_integer(WeightStr, Weight, 10);
  }
}

static std::error_code getAFLCoverage(const StringRef    Seed,
                                      AFLCoverageVector &Cov) {
  Optional<StringRef> Redirects[] = {None, None, None};

  // Create temporary output file
  SmallString<64> OutputPath;
  const auto EC = sys::fs::createTemporaryFile("showmap", "txt", OutputPath);
  if (EC) return EC;

  // Prepare afl-showmap arguments
  SmallVector<StringRef, 12> AFLShowmapArgs{
      AFLShowmapPath, "-m", MemLimit, "-t", Timeout, "-q", "-o", OutputPath};

  if (TargetArgsHasAtAt)
    AFLShowmapArgs.append({"-A", Seed});
  else
    Redirects[/* stdin */ 0] = Seed;

  AFLShowmapArgs.append({"--", TargetProg});
  AFLShowmapArgs.append(TargetArgs.begin(), TargetArgs.end());

  // Run afl-showmap
  sys::ExecuteAndWait(AFLShowmapPath, AFLShowmapArgs, /*env=*/None, Redirects);

  // Parse afl-showmap output
  const auto CovOrErr = MemoryBuffer::getFile(OutputPath);
  if (const auto EC = CovOrErr.getError()) {
    sys::fs::remove(OutputPath);
    return EC;
  }

  SmallVector<StringRef, 0> Lines;
  CovOrErr.get()->getBuffer().split(Lines, '\n');

  AFLTupleID Edge = 0;
  unsigned   Freq = 0;

  for (const auto &Line : Lines) {
    const auto &[EdgeStr, FreqStr] = Line.split(':');

    to_integer(EdgeStr, Edge, 10);
    to_integer(FreqStr, Freq, 10);
    Cov.push_back({Edge, Freq});
  }

  return sys::fs::remove(OutputPath);
}

static void Usage(const char *Argv0) {
  errs() << '\n' << Argv0 << " [ options ] -- /path/to/target_app [...]\n\n";
  errs() << "Required parameters:\n\n";
  errs() << "  -i dir     - Corpus directory\n";
  errs() << "  -o dir     - Output directory\n\n";
  errs() << "Optional parameters:\n\n";
  errs() << "  -p         - Show progress bar\n";
  errs() << "  -m megs    - Memory limit for child process (0 MB)\n";
  errs() << "  -t msec    - Timeout for each seed run (none)\n";
  errs() << "  -e         - Use edge coverage only, ignore hit counts\n";
  errs() << "  -h         - Print this message\n";
  errs() << "  -w weights - CSV containing seed weights (see README)\n\n";

  std::exit(1);
}

static inline void StartTimer(bool ShowProgBar) {
  StartTime = std::chrono::system_clock::now();
}

static inline void EndTimer(bool ShowProgBar) {
  EndTime = std::chrono::system_clock::now();
  Duration =
      std::chrono::duration_cast<std::chrono::seconds>(EndTime - StartTime);

  if (ShowProgBar)
    outs() << '\n';
  else
    outs() << Duration.count() << "s\n";
}

// -------------------------------------------------------------------------- //
// Main function
// -------------------------------------------------------------------------- //

int main(int Argc, char *Argv[]) {
  StringRef   CorpusDir, OutputDir, WeightsFile;
  bool        ShowProgBar = false;
  bool        EdgesOnly = true;
  WeightsMap  Weights;
  int         Opt;
  ProgressBar ProgBar;

  const auto ErrMsg = []() {
    return WithColor(errs(), HighlightColor::Error) << "[-] ";
  };
  const auto WarnMsg = []() {
    return WithColor(errs(), HighlightColor::Warning) << "[-] ";
  };
  const auto SuccMsg = []() {
    return WithColor(outs(), HighlightColor::String) << "[+] ";
  };
  const auto StatMsg = []() {
    return WithColor(outs(), HighlightColor::Remark) << "[*] ";
  };

  // ------------------------------------------------------------------------ //
  // Parse command-line options
  // ------------------------------------------------------------------------ //

  while ((Opt = getopt(Argc, Argv, "+i:o:pm:t:fhw:")) > 0) {
    switch (Opt) {
      case 'i':
        // Input directory
        CorpusDir = optarg;
        break;
      case 'o':
        // Output directory
        OutputDir = optarg;
        break;
      case 'p':
        // Show progres bar
        ShowProgBar = true;
        break;
      case 'm':
        // Memory limit
        MemLimit = optarg;
        break;
      case 't':
        // Timeout
        Timeout = optarg;
        break;
      case 'f':
        // Take into account edge frequency (i.e., number of times each edge was
        // executed) when minimizing
        EdgesOnly = false;
        break;
      case 'h':
        // Help
        Usage(Argv[0]);
        break;
      case 'w':
        // Weights file
        WeightsFile = optarg;
        break;
      default:
        Usage(Argv[0]);
    }
  }

  if (optind == Argc || CorpusDir == "" || OutputDir == "") Usage(Argv[0]);
  if (!sys::fs::is_directory(OutputDir)) {
    ErrMsg() << "Invalid output directory `" << OutputDir << "`\n";
    return 1;
  }

  TargetProg = Argv[optind];
  for (unsigned I = optind + 1; I < Argc; ++I) {
    if (!strcmp(Argv[I], "@@")) TargetArgsHasAtAt = true;
    TargetArgs.push_back(Argv[I]);
  }

  // Find afl-showmap
  const auto AFLShowmapOrErr = sys::findProgramByName("afl-showmap");
  if (const auto EC = AFLShowmapOrErr.getError()) {
    ErrMsg() << "Failed to find afl-showmap. Check your PATH\n";
    return 1;
  }
  AFLShowmapPath = *AFLShowmapOrErr;

  // ------------------------------------------------------------------------ //
  // Parse weights
  //
  // Weights are stored in CSV file mapping a seed file name to an integer
  // greater than zero.
  // ------------------------------------------------------------------------ //

  if (WeightsFile != "") {
    StatMsg() << "Reading weights from `" << WeightsFile << "`... ";
    StartTimer(ShowProgBar);

    const auto WeightsOrErr = MemoryBuffer::getFile(WeightsFile);
    if (const auto EC = WeightsOrErr.getError()) {
      ErrMsg() << "Failed to read weights from `" << WeightsFile
               << "`: " << EC.message() << '\n';
      return 1;
    }

    GetWeights(*WeightsOrErr.get(), Weights);

    EndTimer(ShowProgBar);
  }

  // ------------------------------------------------------------------------ //
  // Traverse corpus directory
  //
  // Find the seed files inside this directory.
  // ------------------------------------------------------------------------ //

  if (!ShowProgBar) StatMsg() << "Locating seeds in `" << CorpusDir << "`... ";
  StartTimer(ShowProgBar);

  std::vector<std::string> SeedFiles;
  std::error_code          EC;
  sys::fs::file_status     Status;

  for (sys::fs::directory_iterator Dir(CorpusDir, EC), DirEnd;
       Dir != DirEnd && !EC; Dir.increment(EC)) {
    const auto &Path = Dir->path();
    EC = sys::fs::status(Path, Status);
    if (EC) {
      WarnMsg() << "Failed to access seed file `" << Path
                << "`: " << EC.message() << ". Skipping...\n";
      continue;
    }
    switch (Status.type()) {
      case sys::fs::file_type::regular_file:
      case sys::fs::file_type::symlink_file:
      case sys::fs::file_type::type_unknown:
        SeedFiles.push_back(Path);
      default:
        /* Ignore */
        break;
    }
    if (EC) {
      ErrMsg() << "Failed to traverse corpus directory `" << CorpusDir
               << "`: " << EC.message() << '\n';
      return 1;
    }
  }

  EndTimer(ShowProgBar);

  // ------------------------------------------------------------------------ //
  // Generate seed coverage
  //
  // Iterate over the corpus directory, which should contain seed files. Execute
  // these seeds in the target program to generate coverage information, and
  // then store this coverage information in the appropriate data structures.
  // ------------------------------------------------------------------------ //

  size_t       SeedCount = 0;
  const size_t NumSeeds = SeedFiles.size();

  if (!ShowProgBar)
    StatMsg() << "Generating coverage for " << NumSeeds << " seeds... ";
  StartTimer(ShowProgBar);

  EvalMaxSAT        Solver(/*nbMinimizeThread=*/0);
  MaxSATSeeds       SeedLiterals;
  MaxSATCoverageMap SeedCoverage;
  AFLCoverageVector Cov;

  for (const auto &SeedFile : SeedFiles) {
    // Execute seed
    Cov.clear();
    if (getAFLCoverage(SeedFile, Cov)) {
      ErrMsg() << "Failed to get coverage for seed " << SeedFile << ": "
               << EC.message() << '\n';
      return 1;
    }

    // Create a literal to represent the seed
    const SeedID SeedLit = Solver.newVar();
    SeedLiterals.push_back({SeedLit, SeedFile});

    // Record the set of seeds that cover a particular edge
    for (const auto &[Edge, Freq] : Cov) {
      if (EdgesOnly) {
        // Ignore edge frequency
        SeedCoverage[Edge].insert(SeedLit);
      } else {
        // Executing edge `E` `N` times means that it was executed `N - 1` times
        for (unsigned I = 0; I < Freq; ++I)
          SeedCoverage[MAX_EDGE_FREQ * Edge + I].insert(SeedLit);
      }
    }

    if ((++SeedCount % 10 == 0) && ShowProgBar)
      ProgBar.update(SeedCount * 100 / NumSeeds, "Generating seed coverage");
  }

  EndTimer(ShowProgBar);

  // ------------------------------------------------------------------------ //
  // Set the hard and soft constraints in the solver
  // ------------------------------------------------------------------------ //

  if (!ShowProgBar) StatMsg() << "Generating constraints... ";
  StartTimer(ShowProgBar);

  SeedCount = 0;

  // Ensure that at least one seed is selected that covers a particular edge
  // (hard constraint)
  std::vector<SeedID> Clauses;
  for (const auto &[_, Seeds] : SeedCoverage) {
    if (Seeds.empty()) continue;

    Clauses.clear();
    for (const auto &Seed : Seeds)
      Clauses.push_back(Seed);

    Solver.addClause(Clauses);

    if ((++SeedCount % 10 == 0) && ShowProgBar)
      ProgBar.update(SeedCount * 100 / SeedCoverage.size(),
                     "Generating clauses");
  }

  // Select the minimum number of seeds that cover a particular set of edges
  // (soft constraint)
  for (const auto &[Literal, Seed] : SeedLiterals)
    Solver.addWeightedClause({-Literal}, Weights[Seed]);

  EndTimer(ShowProgBar);

  // ------------------------------------------------------------------------ //
  // Generate a solution
  // ------------------------------------------------------------------------ //

  StatMsg() << "Solving... ";
  StartTimer(ShowProgBar);

  const bool Solved = Solver.solve();

  EndTimer(/*ShowProgBar=*/false);

  // ------------------------------------------------------------------------ //
  // Print out the solution
  // ------------------------------------------------------------------------ //

  SmallVector<StringRef, 64> Solution;
  SmallString<32>            OutputSeed;

  if (Solved) {
    for (const auto &[ID, Seed] : SeedLiterals)
      if (Solver.getValue(ID) > 0) Solution.push_back(Seed);
  } else {
    ErrMsg() << "Failed to find an optimal solution for `" << CorpusDir
             << "`\n";
    return 1;
  }

  SuccMsg() << "Minimized corpus size: " << Solution.size() << " seeds\n";

  if (!ShowProgBar) StatMsg() << "Copying to `" << OutputDir << "`... ";
  StartTimer(ShowProgBar);

  SeedCount = 0;

  for (const auto &Seed : Solution) {
    OutputSeed = OutputDir;
    sys::path::append(OutputSeed, sys::path::filename(Seed));

    if (const auto EC = sys::fs::copy_file(Seed, OutputSeed)) {
      WarnMsg() << "Failed to copy `" << Seed << "` to `" << OutputDir << "`\n";
    }

    if ((++SeedCount % 10 == 0) && ShowProgBar)
      ProgBar.update(SeedCount * 100 / Solution.size(), "Copying seeds");
  }

  EndTimer(ShowProgBar);
  SuccMsg() << "Done!\n";

  return 0;
}
