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

## 写控制流图
```
很好，再写一条规则：对于java语言，从controller出发，如果有控制流执行到test()，那么就算风险，提示出来
```

### 返回结果
```
import java
import semmle.code.java.dataflow.ControlFlowGraph

/**
 * @name Control flow from controller to test() function
 * @description Identifies control flow paths from controller classes to the test() function, which might indicate a risk.
 * @kind path-problem
 * @id java/controller-to-test-risk
 */

class ControllerToTestConfig extends ControlFlowGraph::Configuration {
  ControllerToTestConfig() { this = "ControllerToTestConfig" }

  override predicate isSource(ControlFlowGraph::ControlFlowNode source) {
    // Consider any method in a controller class as a source
    exists(Method m | 
      m.getDeclaringType().getName().matches("%Controller") and
      source.getNode() = m
    )
  }

  override predicate isSink(ControlFlowGraph::ControlFlowNode sink) {
    // Define the sink as any call to the test() function
    exists(MethodAccess ma |
      ma.getMethod().hasName("test") and
      sink.getNode() = ma
    )
  }
}

from ControllerToTestConfig config, ControlFlowGraph::ControlFlowNode source, ControlFlowGraph::ControlFlowNode sink
where config.hasFlow(source, sink)
select sink, "Control flow from controller to test() function detected, potential risk."
```

## 带净化函数，带入口识别
```
很好，再写一条规则：对于java语言，从所有带@controller注解的函数出发，如果有控制流未经过secure()函数，执行到了test()函数，那么就算风险，提示出来。
```

```
import java
import semmle.code.java.dataflow.ControlFlowGraph

/**
 * @name Unsecured flow from @Controller to test() function
 * @description Identifies control flow paths from @Controller annotated methods to the test() function without passing through secure() function, which might indicate a security risk.
 * @kind path-problem
 * @id java/controller-to-test-unsecured
 */

class ControllerToTestConfig extends ControlFlowGraph::Configuration {
  ControllerToTestConfig() { this = "ControllerToTestConfig" }

  override predicate isSource(ControlFlowGraph::ControlFlowNode source) {
    // Consider any method with @Controller annotation as a source
    exists(Method m | 
      m.hasAnnotation("Controller") and
      source.getNode() = m
    )
  }

  override predicate isSink(ControlFlowGraph::ControlFlowNode sink) {
    // Define the sink as any call to the test() function
    exists(MethodAccess ma |
      ma.getMethod().hasName("test") and
      sink.getNode() = ma
    )
  }

  override predicate isBarrier(ControlFlowGraph::ControlFlowNode barrier) {
    // Define secure() function as a barrier
    exists(MethodAccess ma |
      ma.getMethod().hasName("secure") and
      barrier.getNode() = ma
    )
  }
}

from ControllerToTestConfig config, ControlFlowGraph::ControlFlowNode source, ControlFlowGraph::ControlFlowNode sink
where config.hasFlow(source, sink)
select sink, "Control flow from @Controller to test() function detected without passing through secure(), potential risk."
```
