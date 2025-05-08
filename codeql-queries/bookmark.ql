import javascript
import DataFlow

from DataFlow::MethodCallNode mc, DataFlow::PropRef pr
where
  mc.getReceiver() = pr and
  pr.getPropertyName() = "bookmarks"
select mc.getLocation().getFile().getRelativePath(),
       mc.getLocation().getStartLine(),
       mc.getCalleeName(),
       "Call to chrome.bookmarks." + mc.getCalleeName()
