#include "capture.h"

Capture::Capture(std::vector<char>&& buffer): buffer(std::move(buffer)){};

Capture::Capture(size_t buffer_size): buffer(buffer_size){};

