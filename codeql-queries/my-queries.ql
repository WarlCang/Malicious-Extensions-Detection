import javascript

from VariableDeclarator vd, string file, int line
where
  vd.getDeclStmt() instanceof LetStmt and           
  vd.getBindingPattern() instanceof VarRef and          
  vd.getBindingPattern().getName() = "target" and       
  vd.getInit() instanceof NullLiteral and
  file = vd.getLocation().getFile().getRelativePath() and
  line = vd.getLocation().getStartLine()
select vd, "let target = null (file: " + file + ", line: " + line + ")"
