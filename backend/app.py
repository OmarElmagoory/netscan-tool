from flask import Flask, request, jsonify, send_file
from flask_cors import CORS
from scanner import full_scan
import urllib3, io, datetime, os
from reportlab.lib.pagesizes import A4
from reportlab.lib import colors
from reportlab.lib.styles import ParagraphStyle
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib.units import cm
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
import arabic_reshaper
from bidi.algorithm import get_display

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
app = Flask(__name__)
CORS(app)

FONT_PATH = os.path.join(os.path.dirname(__file__), 'arabic_font.ttf')
pdfmetrics.registerFont(TTFont('Arabic', FONT_PATH))

def ar(text):
    if not text: return ""
    try: return get_display(arabic_reshaper.reshape(str(text)))
    except: return str(text)

@app.after_request
def add_cors(response):
    response.headers['Access-Control-Allow-Origin'] = '*'
    response.headers['Access-Control-Allow-Methods'] = 'GET, POST, OPTIONS'
    response.headers['Access-Control-Allow-Headers'] = 'Content-Type'
    return response

@app.route('/', methods=['GET','OPTIONS'])
def home():
    return jsonify({"status": "WebScan API running", "version": "3.0"})

@app.route('/scan', methods=['POST','OPTIONS'])
def scan():
    if request.method == 'OPTIONS':
        return jsonify({}), 200
    data = request.get_json()
    url = data.get("url","").strip()
    scan_type = data.get("scan_type","both")
    if not url: return jsonify({"error": "URL is required"}), 400
    if not url.startswith("http://") and not url.startswith("https://"):
        url = "https://" + url
    try:
        results = full_scan(url, scan_type)
        return jsonify({
            "url": url, "results": results,
            "summary": {
                "critical": sum(1 for r in results if r.get("severity")=="critical"),
                "medium":   sum(1 for r in results if r.get("severity")=="medium"),
                "low":      sum(1 for r in results if r.get("severity")=="low"),
                "safe":     sum(1 for r in results if r.get("severity")=="safe"),
                "total":    len(results)
            }
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/report', methods=['POST','OPTIONS'])
def generate_report():
    if request.method == 'OPTIONS':
        return jsonify({}), 200
    data = request.get_json()
    url = data.get("url","")
    results = data.get("results",[])
    summary = data.get("summary",{})
    lang = data.get("lang","ar")
    is_ar = lang == "ar"
    fn = "Arabic" if is_ar else "Helvetica"
    fb = "Arabic" if is_ar else "Helvetica-Bold"
    sev_colors = {"critical":colors.HexColor('#ff3b5c'),"medium":colors.HexColor('#ffb340'),"low":colors.HexColor('#3b82f6'),"safe":colors.HexColor('#00e676')}
    sev_bg = {"critical":colors.HexColor('#2a0a10'),"medium":colors.HexColor('#2a1a00'),"low":colors.HexColor('#0a1a2a'),"safe":colors.HexColor('#0a2a1a')}
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=A4, rightMargin=2*cm, leftMargin=2*cm, topMargin=2*cm, bottomMargin=2*cm)
    story = []
    ts = ParagraphStyle('t', fontSize=22, fontName=fb, textColor=colors.HexColor('#00d4ff'), spaceAfter=6, alignment=1)
    ss = ParagraphStyle('s', fontSize=11, fontName=fn, textColor=colors.HexColor('#64748b'), spaceAfter=4, alignment=1)
    sec = ParagraphStyle('sec', fontSize=13, fontName=fb, textColor=colors.white, spaceAfter=8, backColor=colors.HexColor('#1a2235'), leftIndent=8)
    sm = ParagraphStyle('sm', fontSize=8, fontName=fn, textColor=colors.HexColor('#94a3b8'), leading=12)
    fs = ParagraphStyle('fs', fontSize=8, fontName='Helvetica', textColor=colors.HexColor('#00d4ff'), leading=12)
    story.append(Paragraph(ar("تقرير فحص الأمان") if is_ar else "Security Scan Report", ts))
    story.append(Paragraph("Web Security Scanner v3.0", ss))
    story.append(Spacer(1, 0.4*cm))
    now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    info = [[ar("الرابط المفحوص") if is_ar else "Target URL", url],[ar("تاريخ الفحص") if is_ar else "Scan Date", now],[ar("إجمالي النتائج") if is_ar else "Total Findings", str(summary.get("total",0))]]
    it = Table(info, colWidths=[4*cm, 13*cm])
    it.setStyle(TableStyle([('BACKGROUND',(0,0),(0,-1),colors.HexColor('#1a2235')),('TEXTCOLOR',(0,0),(0,-1),colors.HexColor('#00d4ff')),('BACKGROUND',(1,0),(1,-1),colors.HexColor('#111827')),('TEXTCOLOR',(1,0),(1,-1),colors.white),('FONTNAME',(0,0),(-1,-1),fn),('FONTSIZE',(0,0),(-1,-1),9),('GRID',(0,0),(-1,-1),0.5,colors.HexColor('#1e3a5f')),('PADDING',(0,0),(-1,-1),8)]))
    story.append(it)
    story.append(Spacer(1, 0.5*cm))
    story.append(Paragraph(f"  {ar('الملخص') if is_ar else 'Summary'}", sec))
    story.append(Spacer(1, 0.2*cm))
    sl = [ar("حرجة") if is_ar else "Critical", ar("متوسطة") if is_ar else "Medium", ar("منخفضة") if is_ar else "Low", ar("آمن") if is_ar else "Safe"]
    sv = [str(summary.get("critical",0)), str(summary.get("medium",0)), str(summary.get("low",0)), str(summary.get("safe",0))]
    smt = Table([sl,sv], colWidths=[4.25*cm]*4)
    smt.setStyle(TableStyle([('FONTNAME',(0,0),(-1,-1),fb),('FONTSIZE',(0,0),(-1,0),11),('FONTSIZE',(0,1),(-1,1),20),('ALIGN',(0,0),(-1,-1),'CENTER'),('VALIGN',(0,0),(-1,-1),'MIDDLE'),('PADDING',(0,0),(-1,-1),12),('BACKGROUND',(0,0),(0,0),colors.HexColor('#ff3b5c')),('BACKGROUND',(1,0),(1,0),colors.HexColor('#ffb340')),('BACKGROUND',(2,0),(2,0),colors.HexColor('#3b82f6')),('BACKGROUND',(3,0),(3,0),colors.HexColor('#00e676')),('TEXTCOLOR',(0,0),(-1,0),colors.white),('BACKGROUND',(0,1),(0,1),colors.HexColor('#2a0a10')),('BACKGROUND',(1,1),(1,1),colors.HexColor('#2a1a00')),('BACKGROUND',(2,1),(2,1),colors.HexColor('#0a1a2a')),('BACKGROUND',(3,1),(3,1),colors.HexColor('#0a2a1a')),('TEXTCOLOR',(0,1),(0,1),colors.HexColor('#ff3b5c')),('TEXTCOLOR',(1,1),(1,1),colors.HexColor('#ffb340')),('TEXTCOLOR',(2,1),(2,1),colors.HexColor('#3b82f6')),('TEXTCOLOR',(3,1),(3,1),colors.HexColor('#00e676')),('GRID',(0,0),(-1,-1),1,colors.HexColor('#0a0e1a'))]))
    story.append(smt)
    story.append(Spacer(1, 0.6*cm))
    story.append(Paragraph(f"  {ar('النتائج التفصيلية') if is_ar else 'Detailed Findings'}", sec))
    story.append(Spacer(1, 0.3*cm))
    for r in results:
        sev = r.get("severity","low")
        sc = sev_colors.get(sev, colors.grey)
        bg = sev_bg.get(sev, colors.HexColor('#111827'))
        name = ar(r.get("name_ar", r.get("name_en",""))) if is_ar else r.get("name_en","")
        desc = ar(r.get("desc_ar", r.get("desc_en",""))) if is_ar else r.get("desc_en","")
        fix = r.get("fix","")
        page_url = r.get("url","")
        hr = [[Paragraph(f'<font color="white"><b>{sev.upper()}</b></font>', ParagraphStyle('sh', fontSize=9, fontName='Helvetica-Bold')), Paragraph(name, ParagraphStyle('nh', fontSize=10, fontName=fb, textColor=colors.white))]]
        ht = Table(hr, colWidths=[2.2*cm, 14.8*cm])
        ht.setStyle(TableStyle([('BACKGROUND',(0,0),(0,0),sc),('BACKGROUND',(1,0),(1,0),colors.HexColor('#1a2235')),('PADDING',(0,0),(-1,-1),8),('VALIGN',(0,0),(-1,-1),'MIDDLE')]))
        story.append(ht)
        if desc:
            dt = Table([[Paragraph(desc, sm)]], colWidths=[17*cm])
            dt.setStyle(TableStyle([('BACKGROUND',(0,0),(-1,-1),bg),('PADDING',(0,0),(-1,-1),8)]))
            story.append(dt)
        if page_url:
            ut = Table([[Paragraph(f"URL: {page_url}", ParagraphStyle('u', fontSize=7, fontName='Helvetica', textColor=colors.HexColor('#475569')))]], colWidths=[17*cm])
            ut.setStyle(TableStyle([('BACKGROUND',(0,0),(-1,-1),colors.HexColor('#0d1526')),('PADDING',(0,0),(-1,-1),6)]))
            story.append(ut)
        if fix:
            fl = ar("التوصية: ") if is_ar else "FIX: "
            ft = Table([[Paragraph(f'{fl}{fix}', fs)]], colWidths=[17*cm])
            ft.setStyle(TableStyle([('BACKGROUND',(0,0),(-1,-1),colors.HexColor('#0a1628')),('PADDING',(0,0),(-1,-1),8),('LINEBELOW',(0,0),(-1,-1),0.5,colors.HexColor('#1e3a5f'))]))
            story.append(ft)
        story.append(Spacer(1, 0.15*cm))
    story.append(Spacer(1, 0.5*cm))
    story.append(Paragraph(ar("تم إنشاء هذا التقرير بواسطة Web Security Scanner v3.0") if is_ar else "Generated by Web Security Scanner v3.0", ParagraphStyle('footer', fontSize=8, fontName=fn, textColor=colors.HexColor('#64748b'), alignment=1)))
    doc.build(story)
    buffer.seek(0)
    filename = f"webscan_report_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
    return send_file(buffer, as_attachment=True, download_name=filename, mimetype='application/pdf')

if __name__ == "__main__":
    app.run(debug=True, port=5000)
