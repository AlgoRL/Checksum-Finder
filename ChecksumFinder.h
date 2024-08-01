#pragma once
#include <future>
#include <thread>

class ChecksumFinder
{
public:
	static std::string get_checksum(const std::string& path);
};
