#include "maat.h"
#include "maat_rule.h"
#include <gtest/gtest.h>


int main(int argc, char ** argv)
{
	int ret=0;
	::testing::InitGoogleTest(&argc, argv);
	ret=RUN_ALL_TESTS();
	return ret;
}
