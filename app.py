from flask import Flask, render_template, request
import os
from json2 import read_pcap
#from data_extract import read_json
from  json_file_data_extracter.three_way_handshake import search_three_way_handshake
from  json_file_data_extracter.DHCP import *
from  json_file_data_extracter.DNS import DNS
from json_file_data_extracter.three_way_handshake import search_three_way_handshake
from json_file_data_extracter.chart import chart


app = Flask(__name__)

UPLOAD_FOLDER = 'uploads'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER



@app.route('/')
def index():
    return render_template('index.html')

@app.route('/upload', methods=['POST'])
def upload_file():
    if 'file' not in request.files:
        return "No file part"

    file = request.files['file']

    if file.filename == '':
        return "No selected file"

    if file:
        # Save the file with a fixed name 'upload.pcap'
        dst = os.path.join(app.config['UPLOAD_FOLDER'], 'upload.pcap')
        file.save(dst)
        read_pcap()
        #read_json()
        #search_three_way_handshake()
        search_DHCP()
        DNS()
        dhcp_print_statements = search_DHCP()
        dns_print_statements = DNS()
        three_way_handshake_print_statements=search_three_way_handshake()
    # Add more function calls if you have other search functions

    # Write print statements to output HTML file
        output_html = r"templates\output.html"

        with open(output_html, "w") as output_file:
            output_file.write("<html><head><link rel=\"stylesheet\" type=\"text/css\" href=\"C:\\Users\\DELL\\Downloads\\python_app-Copy\\static\\style1.css\"></head><body>")
            output_file.write("<div class=\"container\">")
            output_file.write("<header>Results</header>")
            output_file.write("<form>")
            
            
            for statement in dhcp_print_statements:
                output_file.write(f"<p>{statement}</p>")
            
            for statement in dns_print_statements:
                output_file.write(f"<p>{statement}</p>")
            for statement in three_way_handshake_print_statements:
                output_file.write(f"<p>{statement}</p>")
            output_file.write("</form>")
            output_file.write("</div>")
            output_file.write("</body></html>")
            
        chart()

        ##      delete uploaded file    ##
        os.remove(r"C:\Users\DELL\Downloads\python_app-Copy\uploads\upload.pcap")
        
        webbrowser.open(output_html)
        return "File uploaded successfully"


    

if __name__ == '__main__':
    app.run(debug=True)
    
