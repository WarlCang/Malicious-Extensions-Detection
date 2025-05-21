import javascript
import DataFlow
from DataFlow::MethodCallNode mc, DataFlow::GlobalVarRefNode gvr
where
  mc.getReceiver() = gvr and 
  (
    mc.getCalleeName() = "fetch" or
    mc.getCalleeName() = "sendBeacon" or
    mc.getCalleeName() = "atob" or
    mc.getCalleeName() = "btoa" or
    mc.getCalleeName() = "fromCharCode"
  )
select
  mc.getLocation().getFile().getRelativePath(),
  mc.getLocation().getStartLine(),
  gvr.getName() + "." + mc.getCalleeName(),
  mc.toString()