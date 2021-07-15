/*
 * An optimal fuzzing corpus minimizer.
 *
 * Author: Adrian Herrera
 */

#include <chrono>
#include <cstdint>
#include <dirent.h>
#include <fstream>
#include <iostream>
#include <map>

#include <llvm/ADT/DenseSet.h>
#include <llvm/ADT/DenseMap.h>
#include <llvm/ADT/SmallVector.h>

#include "ProgressBar.h"
#include "EvalMaxSAT.h"

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

/// Pair of tuple (edge) ID and hit count
using AFLTuple =
    std::pair</* Tuple ID */ uint32_t, /* Execution count */ unsigned>;

/// Coverage for a given seed file
using AFLCoverageVector = llvm::SmallVector<AFLTuple, 0>;

/// Maps seed file paths to a weight
using WeightsMap =
    std::map</* Seed file */ std::string, /* Seed weight */ WeightT>;

/// A seed identifier in the MaxSAT solver
using SeedID = int;

/// Maps seed identifiers to seed files
using MaxSATSeeds =
    llvm::SmallVector<std::pair<SeedID, /* Seed file */ std::string>, 0>;

/// Set of literal identifiers
using MaxSATSeedSet = llvm::DenseSet<SeedID>;

/// Maps tuple IDs to the literal identifiers that "cover" that tuple
using MaxSATCoverageMap = llvm::DenseMap<AFLTuple::first_type, MaxSATSeedSet>;

// -------------------------------------------------------------------------- //
// Global variables
// -------------------------------------------------------------------------- //

static std::chrono::time_point<std::chrono::steady_clock> StartTime, EndTime;
static std::chrono::seconds                               Duration;

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

    Weights.emplace(Seed, Weight);
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

void GetAFLCoverage(std::istream &IS, AFLCoverageVector &Cov) {
  std::string Line;

  while (std::getline(IS, Line, '\n')) {
    const size_t   DelimPos = Line.find(':');
    const uint32_t E = std::stoul(Line.substr(0, DelimPos));
    const unsigned Freq = std::stoul(Line.substr(DelimPos + 1));

    Cov.push_back({E, Freq});
  }
}

static void Usage(const char *Argv0) {
  std::cerr << '\n' << Argv0 << " [ options ] -- /path/to/corpus_dir\n\n";
  std::cerr << "Required parameters:\n\n";
  std::cerr << "  -o         - Output WCNF (DIMACS) file\n\n";
  std::cerr << "Optional parameters:\n\n";
  std::cerr << "  -p         - Show progress bar\n";
  std::cerr << "  -e         - Use edge coverage only, ignore hit counts\n";
  std::cerr << "  -h         - Print this message\n";
  std::cerr << "  -w weights - CSV containing seed weights (see README)\n\n";
  std::cerr << std::endl;

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
    std::cout << std::endl;
  else
    std::cout << Duration.count() << 's' << std::endl;
}

int main(int Argc, char *Argv[]) {
  bool        ShowProg = false;
  bool        EdgesOnly = false;
  std::string WeightsFile;
  WeightsMap  Weights;
  int         Opt;
  ProgressBar Prog;

  std::cout << "afl-showmap corpus minimization\n\n";

  // Parse command-line options
  while ((Opt = getopt(Argc, Argv, "+pehw:")) > 0) {
    switch (Opt) {
      case 'p':
        // Show progres bar
        ShowProg = true;
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

  if (optind >= Argc) Usage(Argv[0]);
  const char *CorpusDir = Argv[optind];

  // ------------------------------------------------------------------------ //
  // Parse weights
  //
  // Weights are stored in CSV file mapping a seed file name to an integer
  // greater than zero.
  // ------------------------------------------------------------------------ //

  if (!WeightsFile.empty()) {
    std::cout << "[*] Reading weights from `" << WeightsFile << "`... "
              << std::flush;
    StartTimer(ShowProg);

    std::ifstream IFS(WeightsFile);
    GetWeights(IFS, Weights);
    IFS.close();

    EndTimer(ShowProg);
  }

  std::unique_ptr<EvalMaxSAT> Solver =
      std::make_unique<EvalMaxSAT>(/* nbMinimizeThread */ 0);

  // ------------------------------------------------------------------------ //
  // Get seed coverage
  //
  // Iterate over the corpus directory, which should contain `afl-showmap`-style
  // output files. Read each of these files and store them in the appropriate
  // data structures.
  // ------------------------------------------------------------------------ //

  struct dirent *   DP;
  DIR *             DirFD;
  AFLCoverageVector Cov;

  MaxSATSeeds       SeedLiterals;
  MaxSATCoverageMap SeedCoverage;

  if (!ShowProg)
    std::cout << "[*] Reading coverage in `" << CorpusDir << "`... "
              << std::flush;
  StartTimer(ShowProg);

  if ((DirFD = opendir(CorpusDir)) == nullptr) {
    std::cerr << "[-] Unable to open corpus directory" << std::endl;
    return 1;
  }

  size_t       SeedCount = 0;
  const size_t NumSeeds = GetNumSeeds(DirFD);

  while ((DP = readdir(DirFD)) != nullptr) {
    if (DP->d_type == DT_DIR) continue;

    // Get seed coverage
    std::ifstream IFS(std::string(CorpusDir) + '/' + DP->d_name);
    Cov.clear();
    GetAFLCoverage(IFS, Cov);
    IFS.close();

    // Create a literal to represent the seed
    const SeedID SeedLit = Solver->newVar();
    SeedLiterals.push_back({SeedLit, DP->d_name});

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

    if ((++SeedCount % 10 == 0) && ShowProg)
      Prog.Update(SeedCount * 100 / NumSeeds, "Reading seed coverage");
  }

  closedir(DirFD);
  EndTimer(ShowProg);

  // ------------------------------------------------------------------------ //
  // Set the hard and soft constraints in the solver
  // ------------------------------------------------------------------------ //

  if (!ShowProg) std::cout << "[*] Generating constraints... " << std::flush;
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

  if (!ShowProg) std::cout << "[*] Solving..." << std::flush;
  StartTimer(ShowProg);

  const bool Solved = Solver->solve();

  EndTimer(ShowProg);

  // ------------------------------------------------------------------------ //
  // Print out the solution
  // ------------------------------------------------------------------------ //

  if (Solved) {
    for (const auto &[Literal, Seed] : SeedLiterals)
      std::cout << Seed << ": " << Solver->getValue(Literal) << std::endl;
  } else {
    std::cerr << "[-] Unable to find an optimal solution for " << CorpusDir
              << std::endl;
    return 1;
  }

  return 0;
}
