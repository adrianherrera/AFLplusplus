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

/// AFL tuiple (edge) ID
using AFLTupleID = uint32_t;

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

  for (const auto &Line : Lines) {
    const auto &[Seed, WeightStr] = Line.split(',');

    unsigned Weight;
    if (to_integer(WeightStr, Weight, 10)) {
      Weights.try_emplace(Seed, Weight);
    } else {
      errs() << "[-] Invalid weight for seed `" << Seed << "`. Skipping...\n";
    }
  }
}

static ErrorOr<std::unique_ptr<MemoryBuffer>> GetAFLCoverage(
    const StringRef Seed) {
  // Create temporary output file
  SmallString<256> OutputPath;
  const auto EC = sys::fs::createTemporaryFile("showmap", "out", OutputPath);
  if (EC) return EC;

  // Run afl-showmap
  SmallVector<StringRef, 12> AFLShowmapArgs{AFLShowmapPath,
                                            "-m",
                                            MemLimit,
                                            "-t",
                                            Timeout,
                                            /* Binary mode */ "-b",
                                            /* Quite mode */ "-q",
                                            "-A",
                                            Seed,
                                            "-o",
                                            OutputPath,
                                            "--",
                                            TargetProg};
  AFLShowmapArgs.append(TargetArgs.begin(), TargetArgs.end());
  sys::ExecuteAndWait(AFLShowmapPath, AFLShowmapArgs);

  // Read afl-showmap output
  return MemoryBuffer::getFile(OutputPath);
}

static void Usage(const char *Argv0) {
  errs() << '\n' << Argv0 << " [ options ] -- /path/to/target_app [...]\n\n";
  errs() << "Required parameters:\n\n";
  errs() << "  -i dir     - Corpus directory\n";
  errs() << "Optional parameters:\n\n";
  errs() << "  -p         - Show progress bar\n";
  errs() << "  -m megs    - Memory limit for child process (0 MB)\n";
  errs() << "  -t msec    - Timeout for each seed run (none)\n";
  errs() << "  -e         - Use edge coverage only, ignore hit counts\n";
  errs() << "  -h         - Print this message\n";
  errs() << "  -w weights - CSV containing seed weights (see README)\n\n";

  std::exit(1);
}

static inline void StartTimer(bool ShowProg) {
  StartTime = std::chrono::system_clock::now();
}

static inline void EndTimer(bool ShowProg) {
  EndTime = std::chrono::system_clock::now();
  Duration =
      std::chrono::duration_cast<std::chrono::seconds>(EndTime - StartTime);

  if (ShowProg)
    outs() << '\n';
  else
    outs() << Duration.count() << "s\n";
}

// -------------------------------------------------------------------------- //
// Main function
// -------------------------------------------------------------------------- //

int main(int Argc, char *Argv[]) {
  SmallString<32> CorpusDir;
  bool            ShowProg = false;
  bool            EdgesOnly = false;
  std::string     WeightsFile;
  WeightsMap      Weights;
  int             Opt;
  ProgressBar     Prog;

  outs() << "OptiMin corpus minimization\n\n";

  // ------------------------------------------------------------------------ //
  // Parse command-line options
  // ------------------------------------------------------------------------ //

  while ((Opt = getopt(Argc, Argv, "+i:pm:t:ehw:")) > 0) {
    switch (Opt) {
      case 'i':
        // Input directory
        CorpusDir = optarg;
        break;
      case 'p':
        // Show progres bar
        ShowProg = true;
        break;
      case 'm':
        // Memory limit
        MemLimit = optarg;
        break;
      case 't':
        // Timeout
        Timeout = optarg;
        break;
      case 'e':
        // Solve for edge coverage only (not frequency of edge coverage)
        EdgesOnly = true;
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

  if (optind == Argc || CorpusDir == "") Usage(Argv[0]);

  TargetProg = Argv[optind];
  for (unsigned I = optind + 1; I < Argc; ++I)
    TargetArgs.push_back(Argv[I]);

  // Find afl-showmap
  const auto AFLShowmapOrErr = sys::findProgramByName("afl-showmap");
  if (const auto EC = AFLShowmapOrErr.getError()) {
    errs() << "[-] Failed to find afl-showmap. Check your PATH\n";
    return 1;
  }
  AFLShowmapPath = *AFLShowmapOrErr;

  // ------------------------------------------------------------------------ //
  // Parse weights
  //
  // Weights are stored in CSV file mapping a seed file name to an integer
  // greater than zero.
  // ------------------------------------------------------------------------ //

  if (!WeightsFile.empty()) {
    outs() << "[*] Reading weights from `" << WeightsFile << "`... ";
    StartTimer(ShowProg);

    const auto WeightsOrErr =
        MemoryBuffer::getFile(WeightsFile, /*IsText=*/true);
    if (const auto EC = WeightsOrErr.getError()) {
      errs() << "[-] Unable to read weights from `" << WeightsFile
             << "`: " << EC.message() << '\n';
      return 1;
    }

    GetWeights(*WeightsOrErr.get(), Weights);

    EndTimer(ShowProg);
  }

  // ------------------------------------------------------------------------ //
  // Traverse corpus directory
  //
  // Find the seed files inside this directory.
  // ------------------------------------------------------------------------ //

  if (!ShowProg) outs() << "[*] Finding seeds in `" << CorpusDir << "`... ";
  StartTimer(ShowProg);

  std::vector<std::string> SeedFiles;
  std::error_code          EC;
  sys::fs::file_status     Status;

  for (sys::fs::directory_iterator Dir(CorpusDir, EC), DirEnd;
       Dir != DirEnd && !EC; Dir.increment(EC)) {
    const auto &Path = Dir->path();
    EC = sys::fs::status(Path, Status);
    if (EC) {
      errs() << "[-] Failed to read seed file `" << Path
             << "`: " << EC.message() << '\n';
      return 1;
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
      errs() << "[-] Failed to traverse corpus directory `" << CorpusDir
             << "`: " << EC.message() << '\n';
      return 1;
    }
  }

  EndTimer(ShowProg);

  // ------------------------------------------------------------------------ //
  // Generate seed coverage
  //
  // Iterate over the corpus directory, which should contain seed files. Execute
  // these seeds in the target program to generate coverage information, and
  // then store this coverage information in the appropriate data structures.
  // ------------------------------------------------------------------------ //

  size_t       SeedCount = 0;
  const size_t NumSeeds = SeedFiles.size();

  if (!ShowProg)
    outs() << "[*] Generating coverage for " << NumSeeds << " seeds...";
  StartTimer(ShowProg);

  std::unique_ptr<EvalMaxSAT> Solver =
      std::make_unique<EvalMaxSAT>(/*nbMinimizeThread=*/0);

  MaxSATSeeds       SeedLiterals;
  MaxSATCoverageMap SeedCoverage;

  for (const auto &SeedFile : SeedFiles) {
    // Get seed coverage
    auto CovOrErr = GetAFLCoverage(SeedFile);
    if (const auto EC = CovOrErr.getError()) {
      errs() << "[-] Unable to get coverage for seed " << SeedFile << ": "
             << EC.message() << '\n';
      return 1;
    }
    const auto Cov = std::move(CovOrErr.get());

    // Create a literal to represent the seed
    const SeedID SeedLit = Solver->newVar();
    SeedLiterals.push_back({SeedLit, SeedFile});

    // Record the set of seeds that cover a particular edge
    unsigned Edge = 0;
    for (const char *Ptr = Cov->getBufferStart(), *End = Cov->getBufferEnd();
         Ptr != End; ++Ptr, ++Edge) {
      const unsigned Freq = *Ptr;

      if (!Freq) continue;
      if (EdgesOnly) {
        // Ignore edge frequency
        SeedCoverage[Edge].insert(SeedLit);
      } else {
        // Executing edge `E` `N` times means that it was executed `N - 1` times
        for (unsigned I = 0; I < Freq; ++I)
          SeedCoverage[MAX_EDGE_FREQ * Edge + I].insert(SeedLit);
      }
    }

    if ((++SeedCount % 10 == 0) && ShowProg)
      Prog.Update(SeedCount * 100 / NumSeeds, "Generating seed coverage");
  }

  EndTimer(ShowProg);

  // ------------------------------------------------------------------------ //
  // Set the hard and soft constraints in the solver
  // ------------------------------------------------------------------------ //

  if (!ShowProg) outs() << "[*] Generating constraints... ";
  StartTimer(ShowProg);

  SeedCount = 0;

  // Ensure that at least one seed is selected that covers a particular edge
  // (hard constraint)
  for (const auto &[_, Seeds] : SeedCoverage) {
    if (Seeds.empty()) continue;

    for (const auto &Seed : Seeds)
      Solver->addClause({Seed});

    if ((++SeedCount % 10 == 0) && ShowProg)
      Prog.Update(SeedCount * 100 / SeedCoverage.size(), "Generating clauses");
  }

  // Select the minimum number of seeds that cover a particular set of edges
  // (soft constraint)
  for (const auto &[Literal, Seed] : SeedLiterals)
    Solver->addWeightedClause({-Literal}, Weights[Seed]);

  EndTimer(ShowProg);

  // ------------------------------------------------------------------------ //
  // Generate a solution
  // ------------------------------------------------------------------------ //

  if (!ShowProg) outs() << "[*] Solving...";
  StartTimer(ShowProg);

  const bool Solved = Solver->solve();

  EndTimer(ShowProg);

  // ------------------------------------------------------------------------ //
  // Print out the solution
  // ------------------------------------------------------------------------ //

  if (Solved) {
    for (const auto &[Literal, Seed] : SeedLiterals)
      outs() << Seed << ": " << Solver->getValue(Literal) << '\n';
  } else {
    errs() << "[-] Unable to find an optimal solution for " << CorpusDir
           << '\n';
    return 1;
  }

  return 0;
}
