/*
 * An optimal fuzzing corpus minimizer.
 *
 * Author: Adrian Herrera
 */

#include <chrono>
#include <cstdint>
#include <dirent.h>
#include <fstream>

#include <llvm/ADT/DenseSet.h>
#include <llvm/ADT/DenseMap.h>
#include <llvm/ADT/SmallVector.h>
#include <llvm/ADT/StringExtras.h>
#include <llvm/ADT/StringMap.h>
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

static std::chrono::time_point<std::chrono::steady_clock> StartTime, EndTime;
static std::chrono::seconds                               Duration;

static char *                 TargetProg;
static SmallVector<StringRef, 8> TargetArgs;

static unsigned Timeout = 0;
static unsigned MemLimit = 0;

// This is based on the human class count in `count_class_human[256]` in
// `afl-showmap.c`
static constexpr uint32_t MAX_EDGE_FREQ = 8;
}  // anonymous namespace

void GetWeights(std::istream &IS, WeightsMap &Weights) {
  std::string Line;

  while (std::getline(IS, Line, '\n')) {
    const size_t      DelimPos = Line.find(',');
    const std::string Seed = Line.substr(0, DelimPos).c_str();
    const unsigned    Weight = std::stoul(Line.substr(DelimPos + 1));

    Weights.try_emplace(Seed, Weight);
  }
}

size_t GetNumSeeds(DIR *FD) {
  struct dirent *DP;
  size_t         SeedCount = 0;

  while ((DP = readdir(FD)) != nullptr)
    if (DP->d_type == DT_REG) ++SeedCount;

  rewinddir(FD);

  return SeedCount;
}

ErrorOr<std::unique_ptr<MemoryBuffer>> GetAFLCoverage(const StringRef Seed) {
  // Find afl-showmap
  static const auto AFLShowmapOrErr = sys::findProgramByName("afl-showmap");
  if (const auto EC = AFLShowmapOrErr.getError()) return EC;

  // Create temporary output file
  SmallString<256> OutputPath;
  const auto EC = sys::fs::createTemporaryFile("showmap", "out", OutputPath);
  if (EC) return EC;

  // Run afl-showmap
  SmallVector<StringRef, 12> AFLShowmapArgs{"-m",
                                            utostr(MemLimit),
                                            "-t",
                                            utostr(Timeout),
                                            /* Binary mode */ "-b",
                                            "-A",
                                            Seed,
                                            "-o",
                                            OutputPath,
                                            "--",
                                            TargetProg};
  AFLShowmapArgs.append(TargetArgs.begin(), TargetArgs.end());
  sys::ExecuteAndWait(*AFLShowmapOrErr, AFLShowmapArgs, /*env=*/None,
                      /*redirects=*/{}, Timeout, MemLimit);

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
  StartTime = std::chrono::steady_clock::now();
}

static inline void EndTimer(bool ShowProg) {
  EndTime = std::chrono::steady_clock::now();
  Duration =
      std::chrono::duration_cast<std::chrono::seconds>(EndTime - StartTime);

  if (ShowProg)
    outs() << '\n';
  else
    outs() << Duration.count() << "s\n";
}

int main(int Argc, char *Argv[]) {
  SmallString<32> CorpusDir;
  bool            ShowProg = false;
  bool            EdgesOnly = false;
  std::string     WeightsFile;
  WeightsMap      Weights;
  int             Opt;
  ProgressBar     Prog;

  outs() << "afl-showmap corpus minimization\n\n";

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
        if (strcmp(optarg, "none")) {
          if (!to_integer(optarg, MemLimit, 10)) {
            errs() << "[-] Invalid memory limit: " << optarg << '\n';
            return 1;
          }
        }
        break;
      case 't':
        // Timeout
        if (strcmp(optarg, "none")) {
          if (!to_integer(optarg, Timeout, 10)) {
            errs() << "[-] Invalid timeout: " << optarg << '\n';
            return 1;
          }
        }
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
  for (unsigned I = optind + 1; optind < Argc; ++I)
    TargetArgs.push_back(Argv[I]);

  // ------------------------------------------------------------------------ //
  // Parse weights
  //
  // Weights are stored in CSV file mapping a seed file name to an integer
  // greater than zero.
  // ------------------------------------------------------------------------ //

  if (!WeightsFile.empty()) {
    outs() << "[*] Reading weights from `" << WeightsFile << "`... ";
    StartTimer(ShowProg);

    std::ifstream IFS(WeightsFile);
    GetWeights(IFS, Weights);
    IFS.close();

    EndTimer(ShowProg);
  }

  std::unique_ptr<EvalMaxSAT> Solver =
      std::make_unique<EvalMaxSAT>(/*nbMinimizeThread=*/0);

  // ------------------------------------------------------------------------ //
  // Get seed coverage
  //
  // Iterate over the corpus directory, which should contain `afl-showmap`-style
  // output files. Read each of these files and store them in the appropriate
  // data structures.
  // ------------------------------------------------------------------------ //

  struct dirent *DP;
  DIR *          DirFD;

  MaxSATSeeds       SeedLiterals;
  MaxSATCoverageMap SeedCoverage;

  if (!ShowProg) outs() << "[*] Reading coverage in `" << CorpusDir << "`... ";
  StartTimer(ShowProg);

  if ((DirFD = opendir(CorpusDir.c_str())) == nullptr) {
    errs() << "[-] Unable to open corpus directory\n";
    return 1;
  }

  size_t       SeedCount = 0;
  const size_t NumSeeds = GetNumSeeds(DirFD);

  while ((DP = readdir(DirFD)) != nullptr) {
    if (DP->d_type == DT_DIR) continue;

    // Get seed coverage
    SmallString<32> Seed{CorpusDir};
    sys::path::append(Seed, DP->d_name);
    auto CovOrErr = GetAFLCoverage(Seed);
    if (const auto EC = CovOrErr.getError()) {
      errs() << "[-] Unable to get coverage for seed " << DP->d_name << ": "
             << EC.message() << '\n';
      return 1;
    }
    const auto Cov = std::move(CovOrErr.get());

    // Create a literal to represent the seed
    const SeedID SeedLit = Solver->newVar();
    SeedLiterals.push_back({SeedLit, DP->d_name});

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
      Prog.Update(SeedCount * 100 / NumSeeds, "Reading seed coverage");
  }

  closedir(DirFD);
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
