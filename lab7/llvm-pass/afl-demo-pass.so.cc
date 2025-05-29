#define AFL_LLVM_PASS

#include "llvm/IR/PassManager.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/Instructions.h"
#include "llvm/Passes/PassBuilder.h"
#include "llvm/Passes/PassPlugin.h"

using namespace llvm;

namespace {

class AFLDEMOPass : public PassInfoMixin<AFLDEMOPass> {
public:
  PreservedAnalyses run(Module &M, ModuleAnalysisManager &) {
    LLVMContext &C = M.getContext();
    Type *VoidTy = Type::getVoidTy(C);
    FunctionCallee demo_crash = M.getOrInsertFunction("__demo_crash", VoidTy);

    for (Function &F : M) {
      for (BasicBlock &BB : F) {
        for (Instruction &I : BB) {
          if (auto *CI = dyn_cast<CallInst>(&I)) {
            Function *calledFunc = CI->getCalledFunction();
            if (!calledFunc) continue;
            if (calledFunc->getName() == "system") {
              Value *arg = CI->getArgOperand(0);
              
              // Strip any pointer casts
              arg = arg->stripPointerCasts();
            
              // Skip instrumentation for direct constant global strings
              if (isa<GlobalVariable>(arg)) {
                GlobalVariable *GV = cast<GlobalVariable>(arg);
                if (GV->hasInitializer()) {
                  if (isa<ConstantDataArray>(GV->getInitializer())) {
                    continue; // skip constant system("echo AAA")
                  }
                }
              }
            
              // If it's not a constant string, treat it as potential injection
              IRBuilder<> IRB(CI);
              IRB.CreateCall(demo_crash);
            }
          }
        }
      }
    }
    return PreservedAnalyses::none();
  }
};

} // namespace

extern "C" LLVM_ATTRIBUTE_WEAK ::llvm::PassPluginLibraryInfo llvmGetPassPluginInfo() {
  return {
    LLVM_PLUGIN_API_VERSION, "AFLDEMOPass", "v0.1",
    [](PassBuilder &PB) {
      PB.registerPipelineParsingCallback(
        [](StringRef, ModulePassManager &MPM, ArrayRef<PassBuilder::PipelineElement>) {
          MPM.addPass(AFLDEMOPass());
          return true;
        });
    }
  };
}
