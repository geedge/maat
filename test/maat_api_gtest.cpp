#include <gtest/gtest.h>

#include "../include/maat/maat.h"

TEST(EQ_Test, Always_True) {
  EXPECT_EQ(1, 1);
}

TEST(maat_api, maat_scan_string) {
	int ret = maat_scan_string(nullptr, 0, 0, nullptr, 0, nullptr, nullptr, nullptr);
	EXPECT_EQ(ret, 0);
}

int main(int argc, char ** argv)
{
	int ret=0;
	::testing::InitGoogleTest(&argc, argv);
	ret=RUN_ALL_TESTS();
	return ret;
}
