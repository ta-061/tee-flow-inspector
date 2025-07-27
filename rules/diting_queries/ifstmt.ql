/**
 * @name If stmt
 * @kind query
 * @id cpp/if-stmt
 * @problem.severity warning
 */

 import cpp

from IfStmt is
select is.getControllingExpr().getLocation()
