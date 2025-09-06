#pragma once

#include <memory>
#include <gumbo.h>

struct GumboDeleter {
    void operator()(GumboOutput* output) const {
        if (output) gumbo_destroy_output(&kGumboDefaultOptions, output);
    }
};

using GumboUniquePtr = std::unique_ptr<GumboOutput, GumboDeleter>;

GumboUniquePtr parse_gumbo(const std::string& html) {
    GumboOutput* output = gumbo_parse(html.c_str());
    if (!output) throw ParseException(1001, "Failed to parse HTML");
    return GumboUniquePtr(output);
}