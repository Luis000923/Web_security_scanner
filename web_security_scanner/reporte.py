import json
from datetime import datetime
import html
import openpyxl
from docx import Document
import pdfkit
from flask import Flask, send_file, request

app = Flask(__name__)

def generar_reporte_json(resultados, nombre_archivo="scan_results.json"):
    """Genera un reporte en formato JSON"""
    try:
        with open(nombre_archivo, "w", encoding="utf-8") as f:
            json.dump({
                "fecha": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "resultados": resultados
            }, f, indent=4, ensure_ascii=False)
        print(f"[+] Reporte JSON generado: {nombre_archivo}")
    except Exception as e:
        print(f"[!] Error al generar el reporte JSON: {e}")

def generar_reporte_html(resultados, nombre_archivo="scan_results.html"):
    """Genera un reporte en formato HTML"""
    try:
        html = f"""<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <title>Reporte Web Security Scanner</title>
    <style>
        body {{ font-family: Arial, sans-serif; background: #f4f4f4; color: #222; }}
        h1 {{ background: #0078d7; color: #fff; padding: 10px; }}
        .section {{ background: #fff; margin: 20px 0; padding: 15px; border-radius: 8px; box-shadow: 0 2px 6px #ccc; }}
        .vuln {{ color: #c00; font-weight: bold; }}
        .safe {{ color: #080; font-weight: bold; }}
        .info {{ color: #0078d7; }}
        table {{ width: 100%; border-collapse: collapse; margin-top: 10px; }}
        th, td {{ border: 1px solid #ccc; padding: 6px 10px; text-align: left; }}
        th {{ background: #eee; }}
    </style>
</head>
<body>
    <h1>Reporte Web Security Scanner</h1>
    <div class="section info">
        <b>Descargar reportes:</b>
        <ul>
            <li><a href="scan_results.xlsx" download>Descargar Excel (.xlsx)</a></li>
            <li><a href="scan_results.docx" download>Descargar Word (.docx)</a></li>
            <li><a href="/descargar/pdf">Descargar PDF (.pdf)</a></li>
        </ul>
        <b>Fecha:</b> {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}
    </div>
    <div class="section">
        <h2>Información del servidor</h2>
        <ul>
            <li><b>Server:</b> {resultados.get('server_info', {}).get('server', 'No detectado')}</li>
            <li><b>X-Powered-By:</b> {resultados.get('server_info', {}).get('x_powered_by', 'No detectado')}</li>
            <li><b>Content-Type:</b> {resultados.get('server_info', {}).get('content_type', 'No detectado')}</li>
        </ul>
    </div>
    <div class="section">
        <h2>Vulnerabilidades Detectadas</h2>
        <h3>Inyección SQL</h3>
        {generar_tabla_vulns(resultados.get('sql_injection', []), ["url", "method", "payload", "parameter", "severity"])}
        <h3>XSS</h3>
        {generar_tabla_vulns(resultados.get('xss', []), ["url", "method", "payload", "parameter"])}
        <h3>Inyección NoSQL</h3>
        {generar_tabla_vulns(resultados.get('nosql_injection', []), ["url", "method", "payload", "parameter"])}
        <h3>Redirección Abierta</h3>
        {generar_tabla_vulns(resultados.get('open_redirect', []), ["url", "parameter", "redirected_to"])}
    </div>
    <div class="section">
        <h2>Tecnologías Detectadas</h2>
        <ul>
            {"".join(f"<li><b>{k}:</b> {v}</li>" for k, v in resultados.get('technologies', {}).items())}
        </ul>
    </div>
    <div class="section">
        <h2>Resumen</h2>
        <ul>
            <li><b>Formularios encontrados:</b> {resultados.get('forms_found', 0)}</li>
            <li><b>Parámetros encontrados:</b> {", ".join(resultados.get('parameters_found', []))}</li>
        </ul>
    </div>
    <div class="section">
        <h2>Subdirectorios Encontrados</h2>
        <ul>
            {"".join(f"<li>{html.escape(subdir)}</li>" for subdir in resultados.get('subdirectories', []))}
        </ul>
    </div>
    <div class="section">
        <h2>Subdominios Encontrados</h2>
        <ul>
            {"".join(f"<li>{html.escape(subd)}</li>" for subd in resultados.get('subdomains', []))}
        </ul>
    </div>
    <div class="section info">
        <b>Nota:</b> Este reporte es generado automáticamente por Web Security Scanner.<br>
        Uso educativo y legal únicamente.
    </div>
</body>
</html>
"""
        with open(nombre_archivo, "w", encoding="utf-8") as f:
            f.write(html)
        print(f"[+] Reporte HTML generado: {nombre_archivo}")
    except Exception as e:
        print(f"[!] Error al generar el reporte HTML: {e}")

def generar_tabla_vulns(vulns, campos):
    if not vulns:
        return '<span class="safe">No se encontraron vulnerabilidades.</span>'
    # Añade la columna Gravedad
    html_table = '<table><tr>' + ''.join(f"<th>{campo.capitalize()}</th>" for campo in campos) + "<th>Gravedad</th></tr>"
    for vuln in vulns:
        html_table += "<tr>" + "".join(
            f"<td>{html.escape(str(vuln.get(campo, '')))}</td>" for campo in campos
        ) + f"<td>{html.escape(str(vuln.get('severity', 'Desconocida')))}</td></tr>"
    html_table += "</table>"
    return html_table

def generar_reporte_excel(resultados, nombre_archivo="scan_results.xlsx"):
    """Genera un reporte en formato Excel (XLSX)"""
    wb = openpyxl.Workbook()
    ws = wb.active
    ws.title = "Vulnerabilidades"

    # Encabezados
    headers = ["Tipo", "URL", "Método", "Payload", "Parámetro", "Redirección a"]
    ws.append(headers)

    # Helper para agregar filas
    def agregar_vulns(tipo, vulns, campos):
        for vuln in vulns:
            fila = [tipo]
            for campo in ["url", "method", "payload", "parameter", "redirected_to"]:
                fila.append(vuln.get(campo, ""))
            ws.append(fila)

    # Agregar todas las vulnerabilidades
    agregar_vulns("SQL Injection", resultados.get('sql_injection', []), headers)
    agregar_vulns("XSS", resultados.get('xss', []), headers)
    agregar_vulns("NoSQL Injection", resultados.get('nosql_injection', []), headers)
    agregar_vulns("Open Redirect", resultados.get('open_redirect', []), headers)

    wb.save(nombre_archivo)
    print(f"[+] Reporte Excel generado: {nombre_archivo}")

def generar_reporte_word(resultados, nombre_archivo="scan_results.docx"):
    """Genera un reporte en formato Word (DOCX)"""
    doc = Document()
    doc.add_heading('Reporte Web Security Scanner', 0)

    def agregar_vulns(tipo, vulns):
        doc.add_heading(tipo, level=1)
        if not vulns:
            doc.add_paragraph("No se encontraron vulnerabilidades.")
            return
        table = doc.add_table(rows=1, cols=5)
        hdr_cells = table.rows[0].cells
        hdr_cells[0].text = 'URL'
        hdr_cells[1].text = 'Método'
        hdr_cells[2].text = 'Payload'
        hdr_cells[3].text = 'Parámetro'
        hdr_cells[4].text = 'Redirección a'
        for vuln in vulns:
            row_cells = table.add_row().cells
            row_cells[0].text = str(vuln.get('url', ''))
            row_cells[1].text = str(vuln.get('method', ''))
            row_cells[2].text = str(vuln.get('payload', ''))
            row_cells[3].text = str(vuln.get('parameter', ''))
            row_cells[4].text = str(vuln.get('redirected_to', ''))
    
    agregar_vulns("SQL Injection", resultados.get('sql_injection', []))
    agregar_vulns("XSS", resultados.get('xss', []))
    agregar_vulns("NoSQL Injection", resultados.get('nosql_injection', []))
    agregar_vulns("Open Redirect", resultados.get('open_redirect', []))

    doc.save(nombre_archivo)
    print(f"[+] Reporte Word generado: {nombre_archivo}")

def generar_reporte_pdf(html_file="scan_results.html", pdf_file="scan_results.pdf"):
    """Convierte el reporte HTML a PDF"""
    try:
        import pdfkit
        path_wkhtmltopdf = r'C:\Program Files\wkhtmltopdf\bin\wkhtmltopdf.exe'  # Ajusta si es necesario
        config = pdfkit.configuration(wkhtmltopdf=path_wkhtmltopdf)
        pdfkit.from_file(html_file, pdf_file, configuration=config)
        print(f"[+] Reporte PDF generado: {pdf_file}")
    except Exception as e:
        print(f"[!] Error al generar el PDF: {e}")

def get_severity_and_desc(vuln_type):
        """Devuelve la gravedad y una breve descripción según el tipo de vulnerabilidad"""
        if vuln_type == 'sql':
            return (
                "Alta",
                "La inyección SQL permite a un atacante manipular consultas a la base de datos. Referencia: https://owasp.org/www-community/attacks/SQL_Injection"
            )
        elif vuln_type == 'xss':
            return (
                "Alta",
                "El Cross-Site Scripting (XSS) permite ejecutar scripts maliciosos en el navegador de la víctima. Referencia: https://owasp.org/www-community/attacks/xss/"
            )
        elif vuln_type == 'nosql':
            return (
                "Alta",
                "La inyección NoSQL permite manipular consultas en bases de datos NoSQL. Referencia: https://owasp.org/www-community/attacks/NoSQL_Injection"
            )
        elif vuln_type == 'open_redirect':
            return (
                "Media",
                "La redirección abierta puede ser usada para phishing o robo de credenciales. Referencia: https://owasp.org/www-community/attacks/Unvalidated_Redirects_and_Forwards_Cheat_Sheet"
            )
        else:
            return ("Desconocida", "No se pudo determinar la gravedad.")

@app.route('/descargar/<tipo>')
def descargar(tipo):
    # Carga los resultados desde el JSON o base de datos
    with open('scan_results.json', encoding='utf-8') as f:
        resultados = json.load(f)['resultados']
    if tipo == 'excel':
        generar_reporte_excel(resultados)
        return send_file('scan_results.xlsx', as_attachment=True)
    elif tipo == 'word':
        generar_reporte_word(resultados)
        return send_file('scan_results.docx', as_attachment=True)
    elif tipo == 'pdf':
        generar_reporte_pdf()
        return send_file('scan_results.pdf', as_attachment=True)
    else:
        return "Tipo de reporte no soportado", 400

@app.route('/descargar/pdf')
def descargar_pdf():
    html_file = "scan_results.html"
    pdf_file = "scan_results.pdf"
    path_wkhtmltopdf = r"C:\Program Files\wkhtmltopdf\bin\wkhtmltopdf.exe"  # Ajusta si es necesario
    config = pdfkit.configuration(wkhtmltopdf=path_wkhtmltopdf)
    try:
        pdfkit.from_file(html_file, pdf_file, configuration=config)
        return send_file(pdf_file, as_attachment=True)
    except Exception as e:
        return f"Error al generar el PDF: {e}", 500



