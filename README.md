# openai-learning-codeql-quickstart

## 检测规则用途理解（污点传播）
```
以下是codeql的一条检测规则，让我们一步一步分析，请解释它的含义，和最终检测的问题
---------
/**
 * @name LDAP query built from user-controlled sources
 * @description Building an LDAP query from user-controlled sources is vulnerable to insertion of
 *              malicious LDAP code by the user.
 * @kind path-problem
 * @problem.severity error
 * @security-severity 9.8
 * @precision high
 * @id java/ldap-injection
 * @tags security
 *       external/cwe/cwe-090
 */

import java
import semmle.code.java.dataflow.FlowSources
import semmle.code.java.security.LdapInjectionQuery
import LdapInjectionFlow::PathGraph

from LdapInjectionFlow::PathNode source, LdapInjectionFlow::PathNode sink
where LdapInjectionFlow::flowPath(source, sink)
select sink.getNode(), source, sink, "This LDAP query depends on a $@.", source.getNode(),
  "user-provided value"
```

## 写新的规则
```
很好，我想写一条codeql规则，把所有流入到test()函数的变量都找出来，请帮我写一下这条规则.

```
### 返回内容
```
import java
import semmle.code.java.dataflow.DataFlow

/** 
 * @name Trace data flow to test() function
 * @description Tracks all variables flowing into the test() function.
 * @kind path-problem
 * @id java/trace-to-test-function
 */
class TestFunctionConfig extends DataFlow::Configuration {
  TestFunctionConfig() { this = "TestFunctionConfig" }

  override predicate isSource(DataFlow::Node source) {
    // Consider all variables as potential sources
    source instanceof DataFlow::ExprNode
  }

  override predicate isSink(DataFlow::Node sink) {
    // Define the sink as any call to the test() function
    exists(MethodAccess ma |
      ma.getMethod().hasName("test") and
      sink.asExpr() = ma.getAnArgument()
    )
  }
}

from TestFunctionConfig config, DataFlow::Node source, DataFlow::Node sink
where config.hasFlow(source, sink)
select sink, source, "Data flows into test() function from here."
```
