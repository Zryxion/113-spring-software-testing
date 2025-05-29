#define AFL_LLVM_PASS

#include "llvm/IR/Function.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/Module.h"
#include "llvm/Pass.h"
#include "llvm/Support/raw_ostream.h"

using namespace llvm;

namespace {

struct AFLDemoLegacyPass : public ModulePass {
  static char ID;
  AFLDemoLegacyPass() : ModulePass(ID) {}

  bool runOnModule(Module &M) override {
    LLVMContext &C = M.getContext();
    Type *VoidTy = Type::getVoidTy(C);

    FunctionCallee demo_crash = M.getOrInsertFunction("__demo_crash", VoidTy);

    for (Function &F : M) {
      for (BasicBlock &BB : F) {
        for (auto it = BB.begin(); it != BB.end(); ++it) {
          if (auto *call = dyn_cast<CallInst>(&*it)) {
            Function *callee = call->getCalledFunction();
            if (!callee) continue;

            if (callee->getName() == "system") {
              Value *arg = call->getArgOperand(0);
              if (!isa<ConstantDataArray>(arg->stripPointerCasts())) {
                IRBuilder<> IRB(call);
                IRB.CreateCall(demo_crash);
              }
            }
          }
        }
      }
    }

    return true;
  }
};

char AFLDemoLegacyPass::ID = 0;
static RegisterPass<AFLDemoLegacyPass> X("afl-demo-pass", "AFL++ Demo Legacy Pass");

} // namespace
