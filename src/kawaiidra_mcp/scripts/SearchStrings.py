# @category MCP
# @runtime Jython
import json

# Search for many interesting patterns at once
patterns = ['password', 'key', 'secret', 'token', 'auth', 'login', 'admin', 
            'http', 'url', 'server', 'connect', 'version', 'error', 'debug',
            'crash', 'hack', 'cheat', 'ban', 'master', 'account', 'user',
            'priv', 'crypto', 'ssl', 'cert', 'sign', 'hash', 'md5', 'sha',
            'exploit', 'overflow', 'inject', 'shell', 'cmd', 'exec']

results = {}
data_mgr = currentProgram.getListing()

for data in data_mgr.getDefinedData(True):
    if data.hasStringValue():
        try:
            val = data.getValue()
            if val:
                val_str = str(val)
                val_lower = val_str.lower()
                for pattern in patterns:
                    if pattern in val_lower:
                        if pattern not in results:
                            results[pattern] = []
                        if len(results[pattern]) < 10:
                            results[pattern].append({
                                'address': str(data.getAddress()),
                                'value': val_str[:200]
                            })
        except Exception as e:
            pass

print('=== MCP_RESULT_JSON ===')
print(json.dumps({'success': True, 'results': results}))
print('=== MCP_RESULT_END ===')
