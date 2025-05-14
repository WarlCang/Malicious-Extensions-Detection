import javascript
import DataFlow

from DataFlow::MethodCallNode mc, DataFlow::PropRef pr, DataFlow::GlobalVarRefNode gvr
where
  mc.getReceiver() = pr and
  pr.getBase() = gvr and
  gvr.getName() = "chrome" and
  (
    pr.getPropertyName() = "cookies" or
    pr.getPropertyName() = "history" or
    pr.getPropertyName() = "bookmarks" or
    pr.getPropertyName() = "tabs" or
    pr.getPropertyName() = "scripting" or
    pr.getPropertyName() = "webRequest" or
    pr.getPropertyName() = "storage" or
    pr.getPropertyName() = "identity" or
    pr.getPropertyName() = "management" or
    pr.getPropertyName() = "runtime" or
    pr.getPropertyName() = "alarms" or
    pr.getPropertyName() = "notifications" or
    pr.getPropertyName() = "declarativeNetRequest" or
    pr.getPropertyName() = "webNavigation"
  )
select
  mc.getLocation().getFile().getRelativePath(),
  mc.getLocation().getStartLine(),
  "chrome." + pr.getPropertyName() + "." + mc.getCalleeName(),
  mc.toString()