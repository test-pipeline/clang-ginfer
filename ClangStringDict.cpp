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


// nDPI specific matcher
StatementMatcher StrcmpMatcher = stringLiteral(
        hasAncestor(
                callExpr(
                        hasDescendant(
                                declRefExpr(
                                   hasDeclaration(
                                           namedDecl(anyOf(
                                                   hasName("strcmp"),
                                                   hasName("__builtin_strcmp"),
                                                   hasName("strncmp"),
                                                   hasName("__builtin_strncmp"),
                                                   hasName("memcmp"),
                                                   hasName("__builtin_memcmp"),
                                                   hasName("memmove"),
                                                   hasName("__builtin_memmove"),
                                                   hasName("unaligned_memcpy"),
                                                   hasName("unaligned_memcmp")
                                           )
                                           ))))))).bind("strcmp");

// libxml2 specific matcher
StatementMatcher xmlcharMatcher = stringLiteral(
        hasAncestor(
                callExpr(
                        hasDescendant(
                                declRefExpr(
                                        hasDeclaration(
                                                namedDecl(anyOf(
                                                        hasName("xmlBufferWriteChar"),
                                                        hasName("xmlOutputBufferWrite")
                                                )
                                                )
                                        )
                                )
                        )
                )
        )
).bind("xml");

// woff2 specific matcher
DeclarationMatcher woff2constintMatcher = varDecl(
        allOf(
                hasType(isConstQualified()),
                hasDescendant(integerLiteral().bind("woff2int")))
);

// re2 specific matcher
StatementMatcher re2charlitMatcher = characterLiteral(
        hasAncestor(
                cxxMethodDecl()
        )
).bind("re2char");

// Generic
StatementMatcher IntLitMatcher = integerLiteral(anyOf(
        hasParent(binaryOperator(hasAncestor(ifStmt()))),
        hasAncestor(caseStmt())
//        hasParent(callExpr())
)).bind("intlit");

StatementMatcher StrLitMatcher = stringLiteral(anyOf(
        hasParent(binaryOperator(hasAncestor(ifStmt()))),
        hasParent(caseStmt())
//        hasParent(callExpr())
)).bind("strlit");

StatementMatcher CharLitMatcher = characterLiteral(anyOf(
        hasParent(binaryOperator(hasAncestor(ifStmt()))),
        hasParent(caseStmt())
//        hasParent(callExpr())
)).bind("charlit");

class MatchPrinter : public MatchFinder::MatchCallback {
public :
    void printToken(StringRef token) {
        size_t tokenlen = token.size();
        if ((tokenlen == 0) || (tokenlen > 128))
            return;
        llvm::outs() << "\"" + token + "\"" << "\n";
    }

    void prettyPrintIntString(std::string inString) {
        if (inString.empty())
            return;
#if 1
        size_t inStrLen = inString.size();
        if (inStrLen % 2) {
            inString.insert(0, "0");
            inStrLen++;
        }
        for (size_t i = 0; i < (2 * inStrLen); i+=4) {
            inString.insert(i, "\\x");
        }
#else
        inString.insert(0, "0x");
#endif
        printToken(inString);
    }

    void formatIntLiteral(const IntegerLiteral *IL) {
        std::string inString = IL->getValue().toString(16, false);
        prettyPrintIntString(inString);
    }

    void formatCharLiteral(const CharacterLiteral *CL) {
        unsigned value = CL->getValue();
        std::string valString = llvm::APInt(8, value).toString(16, false);
        prettyPrintIntString(valString);
    }

    virtual void run(const MatchFinder::MatchResult &Result) {
        if (const clang::StringLiteral *SL = Result.Nodes.getNodeAs<clang::StringLiteral>("strcmp"))
            printToken(SL->getString());
        if (const clang::StringLiteral *SL = Result.Nodes.getNodeAs<clang::StringLiteral>("strlit"))
            printToken(SL->getString());
        if (const clang::IntegerLiteral *IL = Result.Nodes.getNodeAs<clang::IntegerLiteral>("intlit"))
            formatIntLiteral(IL);
        if (const clang::StringLiteral *SL = Result.Nodes.getNodeAs<clang::StringLiteral>("xml"))
            printToken(SL->getString());
        if (const clang::IntegerLiteral *IL = Result.Nodes.getNodeAs<clang::IntegerLiteral>("woff2int"))
            formatIntLiteral(IL);
        if (const clang::CharacterLiteral *CL = Result.Nodes.getNodeAs<clang::CharacterLiteral>("charlit"))
            formatCharLiteral(CL);
    }
};

int main(int argc, const char **argv) {
    CommonOptionsParser OptionsParser(argc, argv, MyToolCategory);
    ClangTool Tool(OptionsParser.getCompilations(),
                   OptionsParser.getSourcePathList());
    MatchPrinter Printer;
    MatchFinder Finder;
    Finder.addMatcher(IntLitMatcher, &Printer);
    Finder.addMatcher(StrLitMatcher, &Printer);
    Finder.addMatcher(CharLitMatcher, &Printer);
    Finder.addMatcher(StrcmpMatcher, &Printer);
//    Finder.addMatcher(xmlcharMatcher, &Printer);
//    Finder.addMatcher(woff2constintMatcher, &Printer);
    return Tool.run(newFrontendActionFactory(&Finder).get());
}