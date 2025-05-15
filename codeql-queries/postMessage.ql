import javascript
import DataFlow

from DataFlow::MethodCallNode mc, DataFlow::PropRef pr,DataFlow::GlobalVarRefNode gvr
where
  mc.getReceiver() = pr and 
  pr.getBase() = gvr and
  mc.getCalleeName() = "postMessage"
select
  mc.getLocation().getFile().getRelativePath(),
  mc.getLocation().getStartLine(),
  gvr.getName() + "." + pr.getPropertyName() + "." + mc.getCalleeName(),
  mc.toString()