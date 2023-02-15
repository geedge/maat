#include "maat.h"

#include <gtest/gtest.h>

TEST(EQ_Test, Always_True) {
  EXPECT_EQ(1, 1);
}

int main(int argc, char ** argv)
{
	int ret=0;
	::testing::InitGoogleTest(&argc, argv);
	ret=RUN_ALL_TESTS();
	return ret;
}