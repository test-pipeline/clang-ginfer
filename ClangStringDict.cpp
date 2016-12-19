#include "clang/AST/ASTConsumer.h"
#include "clang/AST/RecursiveASTVisitor.h"
#include "clang/Frontend/CompilerInstance.h"
#include "clang/Frontend/FrontendAction.h"
#include "clang/Tooling/Tooling.h"
#include "clang/ASTMatchers/ASTMatchers.h"
#include "clang/ASTMatchers/ASTMatchFinder.h"

// Declares clang::SyntaxOnlyAction.
#include "clang/Frontend/FrontendActions.h"
#include "clang/Tooling/CommonOptionsParser.h"
// Declares llvm::cl::extrahelp.
#include "llvm/Support/CommandLine.h"
#include "llvm/Support/Regex.h"

using namespace clang::tooling;
using namespace llvm;

using namespace clang;
using namespace clang::ast_matchers;

// Apply a custom category to all command-line options so that they are the
// only ones displayed.
static cl::OptionCategory MyToolCategory("clang-sdict options");

// CommonOptionsParser declares HelpMessage with a description of the common
// command-line options related to the compilation database and input files.
// It's nice to have this help message in all tools.
static cl::extrahelp CommonHelp(CommonOptionsParser::HelpMessage);

// A help message for this specific tool can be added afterwards.
static cl::extrahelp MoreHelp("\nTakes a compilation database and spits out CString Literals in source files\n");

StatementMatcher StrcmpMatcher = stringLiteral(
        hasAncestor(
                callExpr(
                        hasDescendant(
                                declRefExpr(
                                   hasDeclaration(
                                           namedDecl(anyOf(
                                                   hasName("strcmp"),
                                                   hasName("strncmp"),
                                                   hasName("memcmp")
                                           )
                                           ))))))).bind("strcmp");

StatementMatcher IntLitMatcher = integerLiteral(
        hasAncestor(
                ifStmt())).bind("intlit");

//StatementMatcher CaseStmtIntMatcher = integerLiteral(
//        hasParent(
//                caseStmt())).bind("caseintlit");
//
//StatementMatcher CaseStmtStrMatcher = stringLiteral(
//        hasParent(
//                caseStmt())).bind("casestrlit");

//TypeMatcher RecordMatcher = recordType();
//        hasDeclaration(
//                namedDecl(
//                        matchesName("*header*")
//                )
//        )).bind("recordtype");

//StatementMatcher HeaderRecMathcer = namedDecl(
//        allOf(
//                matchesName("*header*"),
//                hasType(
//                        recordType()
//                ))).bind("headerstruct");

DeclarationMatcher HeaderRecMatcher = namedDecl(
        matchesName(".*header.*"),
        recordDecl()
        ).bind("headerstruct");

class MatchPrinter : public MatchFinder::MatchCallback {
public :
    void printToken(StringRef token) {
        size_t tokenlen = token.size();
        if ((tokenlen == 0) || (tokenlen > 128))
            return;
        llvm::outs() << "\"" + token + "\"" << "\n";
    }

    void formatIntLiteral(const IntegerLiteral *IL) {
        std::string inString = IL->getValue().toString(16, false);
        if (inString.empty())
            return;
        size_t inStrLen = inString.size();
        if (inStrLen % 2) {
            inString.insert(0, "0");
            inStrLen++;
        }
        for (size_t i = 0; i < (2 * inStrLen); i+=4) {
            inString.insert(i, "\\x");
        }
        printToken(inString);
    }

    virtual void run(const MatchFinder::MatchResult &Result) {
        if (const StringLiteral *SL = Result.Nodes.getNodeAs<clang::StringLiteral>("strcmp"))
            printToken(SL->getString());
//        if (const StringLiteral *SL = Result.Nodes.getNodeAs<clang::StringLiteral>("casestrlit"))
//            printToken(SL->getString());
        if (const IntegerLiteral *IL = Result.Nodes.getNodeAs<clang::IntegerLiteral>("intlit"))
            formatIntLiteral(IL);
//        if (const IntegerLiteral *IL = Result.Nodes.getNodeAs<clang::IntegerLiteral>("caseintlit"))
//            formatIntLiteral(IL);
        if (const NamedDecl *ND = Result.Nodes.getNodeAs<clang::NamedDecl>("headerstruct")) {
            printToken(ND->getName());
        }
    }
};

int main(int argc, const char **argv) {
    CommonOptionsParser OptionsParser(argc, argv, MyToolCategory);
    ClangTool Tool(OptionsParser.getCompilations(),
                   OptionsParser.getSourcePathList());
    MatchPrinter Printer;
    MatchFinder Finder;
    Finder.addMatcher(IntLitMatcher, &Printer);
    Finder.addMatcher(StrcmpMatcher, &Printer);
//    Finder.addMatcher(CaseStmtIntMatcher, &Printer);
//    Finder.addMatcher(CaseStmtStrMatcher, &Printer);
//    Finder.addMatcher(HeaderRecMatcher, &Printer);

    return Tool.run(newFrontendActionFactory(&Finder).get());
}