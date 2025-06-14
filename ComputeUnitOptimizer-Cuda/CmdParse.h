#ifndef CMDPARSE_H
#define CMDPARSE_H

#include <string>
#include <vector>

// Represents a single parsed command-line argument
class OptArg {
public:
    std::string option;
    std::string arg;
    bool hasArg;

    // Checks if this option matches a given short or long form.
    // This method is now const-correct.
    bool equals(std::string shortForm, std::string longForm = "") const
    {
        return (!shortForm.empty() && option == shortForm) || (!longForm.empty() && option == longForm);
    }
};

// A simple command-line parser
class CmdParse {
private:
    std::vector<OptArg> options;
    std::vector<OptArg> args;
    std::vector<std::string> operands;

public:
    void add(std::string shortForm, std::string longForm, bool hasArg);
    void parse(int argc, char** argv);
    std::vector<OptArg> getArgs();
    std::vector<std::string> getOperands();
};

#endif
