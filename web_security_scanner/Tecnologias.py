

TECNOLOGIAS = { 
            # Servidores web
            'servers': {
                'Apache': ['Apache', 'httpd'],
                'Nginx': ['nginx'],
                'IIS': ['Microsoft-IIS', 'IIS'],
                'LiteSpeed': ['LiteSpeed'],
                'Tomcat': ['Apache-Coyote', 'Tomcat'],
                'Node.js': ['Node.js', 'Express', 'nodejsExpress'],
                'Cloudflare': ['cloudflare', 'cloudflare-nginx']
            },
            # Lenguajes del lado del servidor
            'languages': {
                'PHP': ['PHP', 'X-Powered-By: PHP', 'PHPSESSID'],
                'ASP.NET': ['ASP.NET', 'X-AspNet-Version', '__VIEWSTATE'],
                'Java': ['Java', 'JSP', 'Servlet', 'X-Powered-By: JSP'],
                'Python': ['Python', 'Django', 'Pyramid', 'Flask', 'wsgi', 'Werkzeug'],
                'Ruby': ['Ruby', 'Ruby on Rails', 'Sinatra', 'Passenger'],
                'Perl': ['Perl', 'CGI-Perl']
            },
            # CMS y Frameworks
            'cms': {
                'WordPress': ['wp-content', 'wp-includes', 'WordPress', '/wp-', 'Powered by WordPress'],
                'Joomla': ['Joomla', 'com_content', '/administrator/', 'mosConfig'],
                'Drupal': ['Drupal', 'drupal.js', 'drupal.min.js', '/sites/default/files/', 'Drupal.settings'],
                'Magento': ['Magento', 'Mage.', '/skin/frontend/', '/js/mage/'],
                'Shopify': ['Shopify', '/cdn.shopify.com/', 'Shopify.theme'],
                'PrestaShop': ['PrestaShop', 'prestashop.com', '/themes/prestashop/'],
                'TYPO3': ['TYPO3', 'typo3temp', 'typo3conf'],
                'Blogger': ['blogger.com', 'blogspot.com'],
                'Wix': ['wixstatic.com', 'wix.com', 'Wix.com']
            },
            # Frameworks y librerías frontend
            'frontend': {
                'jQuery': ['jquery', 'jQuery'],
                'Bootstrap': ['bootstrap', 'bootstrap.min.css', 'bootstrap.min.js'],
                'React': ['react.js', 'react.min.js', 'react-dom', 'ReactDOM'],
                'Angular': ['angular.js', 'ng-app', 'ng-controller', 'angular.min.js'],
                'Vue.js': ['vue.js', 'vue.min.js', 'v-bind', 'v-on'],
                'Font Awesome': ['font-awesome', 'fontawesome'],
                'Tailwind CSS': ['tailwind', 'tailwindcss'],
                'MUI (Material UI)': ['mui', 'material-ui'],
                'Bulma': ['bulma.css', 'bulma.min.css']
            },
            # Bases de datos
            'databases': {
                'MySQL': ['MySQL', 'mysqli', 'MariaDB'],
                'PostgreSQL': ['PostgreSQL', 'pg_', 'pgsql'],
                'Oracle': ['Oracle', 'ORA-'],
                'SQLite': ['SQLite'],
                'MongoDB': ['MongoDB', 'mongo'],
                'Microsoft SQL Server': ['SQL Server', 'MSSQL']
            },
            # JavaScript frameworks y librerías
            'js_frameworks': {
                'lodash': ['lodash.js', 'lodash.min.js', '_'],
                'Moment.js': ['moment.js', 'moment.min.js'],
                'D3.js': ['d3.js', 'd3.min.js'],
                'Chart.js': ['chart.js', 'Chart.min.js'],
                'Three.js': ['three.js', 'three.min.js'],
                'Socket.io': ['socket.io', 'socket.io.js'],
                'Axios': ['axios.js', 'axios.min.js'],
                'Redux': ['redux.js', 'redux.min.js']
            },
            # Análisis y marketing
            'analytics': {
                'Google Analytics': ['google-analytics.com', 'ga.js', 'analytics.js', 'gtag'],
                'Google Tag Manager': ['gtm.js', 'googletagmanager.com'],
                'Facebook Pixel': ['connect.facebook.net', 'fbevents.js', 'fbq('],
                'Hotjar': ['hotjar.com', 'hotjar.js'],
                'Matomo': ['matomo.js', 'piwik.js', 'matomo.php'],
                'Adobe Analytics': ['sc.omtrdc.net', 's_code.js', 'adobe analytics']
            },
            # Miscelánea
            'misc': {
                'Google reCAPTCHA': ['recaptcha', 'grecaptcha'],
                'Cloudflare CDN': ['cdnjs.cloudflare.com', 'cloudflare.com'],
                'Amazon S3': ['s3.amazonaws.com'],
                'Stripe': ['stripe.com', 'stripe.js'],
                'PayPal': ['paypal.com', 'paypalobjects.com'],
                'Varnish Cache': ['X-Varnish', 'Via: varnish'],
                'Netlify': ['netlify.app', 'netlify.com'],
                'Vercel': ['vercel.app', 'vercel.com']
            }
        }