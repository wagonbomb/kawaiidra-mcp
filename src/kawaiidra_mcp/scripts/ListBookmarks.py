# @category MCP
# @runtime Jython
import json

def _safe_str(val):
    try:
        return str(val)
    except UnicodeEncodeError:
        try:
            return val.encode("ascii", "ignore")
        except:
            return ""

category_filter = json.loads('"MCP_Test"')
limit = 100

bm_mgr = currentProgram.getBookmarkManager()
results = []

for bm in bm_mgr.getBookmarksIterator():
    if len(results) >= limit:
        break

    bm_category = _safe_str(bm.getCategory())
    if category_filter and bm_category != category_filter:
        continue

    results.append({
        "address": str(bm.getAddress()),
        "type": _safe_str(bm.getTypeString()),
        "category": bm_category,
        "comment": _safe_str(bm.getComment())
    })

print("=== MCP_RESULT_JSON ===")
print(json.dumps({"success": True, "count": len(results), "bookmarks": results}))
print("=== MCP_RESULT_END ===")
