#include <gtest/gtest.h>
#include <glog/logging.h>
#include "htparse.h"
#include <memory>

class HtParseTest : public ::testing::Test {
 protected:
  virtual void SetUp() {
	  parser.reset(htparser_new());
	  hooks.reset(new htparse_hooks());
  }

  // virtual void TearDown() {}
  std::auto_ptr<IHTParser> parser;
  std::auto_ptr<htparse_hooks> hooks;
};

TEST_F(HtParseTest, InvalidRequest) {
	 const char  * test_1 = "GET / HTTP/1.0\r\ne\r\n";
	 parser->init(htp_type_request);
	 parser->run(hooks.get(), test_1, strlen(test_1));
	 //ASSERT_EQ(htparse_error_none,parser->get_error())<<parser->get_strerror();
	 //ASSERT_EQ(htparse_error_inval_reqline,parser->get_error())<<parser->get_strerror();	 
}

class MyEnvironment :public ::testing::Environment {
	public:
  virtual ~MyEnvironment() {}
  // Override this to define how to set up the environment.
  virtual void SetUp() {
	  google::InitGoogleLogging("myunitest");
  }
  // Override this to define how to tear down the environment.
  virtual void TearDown() {}
};
int main(int argc, char **argv) {
  ::testing::InitGoogleTest(&argc, argv);
  ::testing::AddGlobalTestEnvironment(new MyEnvironment());
  return RUN_ALL_TESTS();
}
