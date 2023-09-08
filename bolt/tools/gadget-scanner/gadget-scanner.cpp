#include "bolt/Utils/CommandLineOpts.h"
#include "llvm/MC/TargetRegistry.h"
#include "llvm/Support/CommandLine.h"
#include "llvm/Support/Errc.h"
#include "llvm/Support/PrettyStackTrace.h"
#include "llvm/Support/Signals.h"
#include "llvm/Support/TargetSelect.h"
#include "llvm/Support/VirtualFileSystem.h"

#define DEBUG_TYPE "bolt"

using namespace llvm;
//using namespace bolt;

namespace opts {

static cl::OptionCategory *GadgetScannerCategories[] = {&GadgetScannerCategory};

static cl::opt<std::string> InputFilename(cl::Positional,
                                          cl::desc("<executable>"),
                                          cl::Required,
                                          cl::cat(GadgetScannerCategory),
                                          cl::sub(cl::SubCommand::getAll()));

} // namespace opts

static StringRef ToolName="gadget-scanner";

static void report_error(StringRef Message, std::error_code EC) {
  assert(EC);
  errs() << ToolName << ": '" << Message << "': " << EC.message() << ".\n";
  exit(1);
}

void ParseCommandLine(int argc, char **argv) {
  cl::HideUnrelatedOptions(ArrayRef(opts::GadgetScannerCategories));
  // Register the target printer for --version.
  //cl::AddExtraVersionPrinter(printBoltRevision);
  cl::AddExtraVersionPrinter(TargetRegistry::printRegisteredTargetsForVersion);

  cl::ParseCommandLineOptions(argc, argv,
                              "GadgetScanner\n");

  //if (opts::OutputFilename.empty()) {
  //  errs() << ToolName << ": expected -o=<output file> option.\n";
  //  exit(1);
  //}
}

int main(int argc, char **argv) {
  // Print a stack trace if we signal out.
  sys::PrintStackTraceOnErrorSignal(argv[0]);
  PrettyStackTraceProgram X(argc, argv);

  llvm_shutdown_obj Y; // Call llvm_shutdown() on exit.

  // Initialize targets and assembly printers/parsers.
  llvm::InitializeAllTargetInfos();
  llvm::InitializeAllTargetMCs();
  llvm::InitializeAllAsmParsers();
  llvm::InitializeAllDisassemblers();

  llvm::InitializeAllTargets();
  llvm::InitializeAllAsmPrinters();

  ParseCommandLine(argc, argv);

  if (!sys::fs::exists(opts::InputFilename))
    report_error(opts::InputFilename, errc::no_such_file_or_directory);

  return EXIT_SUCCESS;
}