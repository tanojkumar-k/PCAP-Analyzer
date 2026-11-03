import dash
from dash import dcc, html, Input, Output, State
import dash_bootstrap_components as dbc
import plotly.express as px
import pandas as pd
from scapy.all import rdpcap, IP, TCP, UDP, ICMP
import base64
import os
import tempfile

app = dash.Dash(__name__, external_stylesheets=[dbc.themes.FLATLY])

app.layout = dbc.Container([
    html.H2("Network PCAP Analyzer", className="text-center mt-4 mb-4"),
    
    dcc.Upload(
        id='upload-pcap',
        children=html.Div(['Drag and Drop your .pcap file or ', html.A('Select File')]),
        style={
            'width': '100%', 'height': '60px', 'lineHeight': '60px',
            'borderWidth': '2px', 'borderStyle': 'dashed',
            'borderRadius': '10px', 'textAlign': 'center', 'marginBottom': '20px'
        },
        multiple=False
    ),
    
    html.Div(id='upload-status', className="text-center mb-4"),
    
    dbc.Row([
        dbc.Col(dcc.Graph(id='protocol-pie-chart'), md=6),
        dbc.Col(dcc.Graph(id='top-ip-bar-chart'), md=6)
    ])
])

@app.callback(
    [Output('protocol-pie-chart', 'figure'),
     Output('top-ip-bar-chart', 'figure'),
     Output('upload-status', 'children')],
    [Input('upload-pcap', 'contents')],
    [State('upload-pcap', 'filename')]
)
def update_dashboard(contents, filename):
    if contents is None:
        # Default empty charts
        return px.pie(title="Protocol Distribution"), px.bar(title="Top 5 Active IPs"), ""

    if not filename.endswith('.pcap'):
        return px.pie(title="Protocol Distribution"), px.bar(title="Top 5 Active IPs"), "Error: Please upload a valid .pcap file."

    # Decode and save the uploaded file temporarily
    content_type, content_string = contents.split(',')
    decoded = base64.b64decode(content_string)
    
    temp_dir = tempfile.mkdtemp()
    temp_path = os.path.join(temp_dir, filename)
    
    with open(temp_path, 'wb') as f:
        f.write(decoded)

    try:
        # Parse PCAP with Scapy
        packets = rdpcap(temp_path)
        data = []
        
        for pkt in packets:
            if IP in pkt:
                src_ip = pkt[IP].src
                protocol = "Other"
                if TCP in pkt:
                    protocol = "TCP"
                elif UDP in pkt:
                    protocol = "UDP"
                elif ICMP in pkt:
                    protocol = "ICMP"
                
                data.append({"Source IP": src_ip, "Protocol": protocol})
                
        df = pd.DataFrame(data)
        
        # Cleanup temp file
        os.remove(temp_path)
        os.rmdir(temp_dir)
        
        if df.empty:
            return px.pie(title="Protocol Distribution"), px.bar(title="Top 5 Active IPs"), "No IP traffic found in this file."

        # 1. Protocol Pie Chart
        protocol_counts = df['Protocol'].value_counts().reset_index()
        protocol_counts.columns = ['Protocol', 'Count']
        fig_pie = px.pie(protocol_counts, names='Protocol', values='Count', title='Protocol Distribution')

        # 2. Top 5 Active IPs Bar Chart
        top_ips = df['Source IP'].value_counts().head(5).reset_index()
        top_ips.columns = ['Source IP', 'Packet Count']
        fig_bar = px.bar(top_ips, x='Source IP', y='Packet Count', title='Top 5 Active Source IPs', color='Source IP')

        return fig_pie, fig_bar, f"Successfully analyzed: {filename}"

    except Exception as e:
        return px.pie(title="Protocol Distribution"), px.bar(title="Top 5 Active IPs"), f"Error analyzing file: {str(e)}"

if __name__ == '__main__':
    app.run(debug=True)