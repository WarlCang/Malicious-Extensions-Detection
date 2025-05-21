import javascript
import DataFlow
from DataFlow::GlobalVarRefNode gvr
where
  gvr.getName() = "fetch" 
select
  gvr.getLocation().getFile().getRelativePath(),
  gvr.getLocation().getStartLine(),
  gvr.getName(),
  gvr.toString()