import pyshark
import pandas as pd
import numpy as np
from sklearn.preprocessing import StandardScaler
from sklearn.ensemble import IsolationForest
import plotly.express as px
import plotly.graph_objs as go
import dash
from dash import dcc, html
from dash.dependencies import Input, Output
import threading
import socket
import json
import time

class NetworkTrafficAnalyzer:
    def __init__(self, interface='eth0', capture_duration=60):
        """
        Initialize the Network Traffic Analyzer
        
        :param interface: Network interface to capture traffic from
        :param capture_duration: Duration of each capture cycle in seconds
        """
        self.interface = interface
        self.capture_duration = capture_duration
        self.traffic_data = []
        self.anomalies = []
        
    def capture_network_traffic(self):
        """
        Capture network packets using pyshark
        """
        capture = pyshark.LiveCapture(interface=self.interface)
        
        start_time = time.time()
        for packet in capture.sniff_continuously(packet_count=1000):
            if time.time() - start_time > self.capture_duration:
                break
            
            try:
                packet_info = {
                    'timestamp': packet.sniff_time,
                    'source_ip': packet.ip.src if hasattr(packet, 'ip') else 'N/A',
                    'destination_ip': packet.ip.dst if hasattr(packet, 'ip') else 'N/A',
                    'protocol': packet.transport_layer if hasattr(packet, 'transport_layer') else 'N/A',
                    'packet_length': int(packet.length),
                    'source_port': packet[packet.transport_layer].srcport if hasattr(packet, packet.transport_layer) else 'N/A',
                    'destination_port': packet[packet.transport_layer].dstport if hasattr(packet, packet.transport_layer) else 'N/A'
                }
                self.traffic_data.append(packet_info)
            except Exception as e:
                print(f"Error processing packet: {e}")
        
        return pd.DataFrame(self.traffic_data)
    
    def preprocess_data(self, df):
        """
        Preprocess network traffic data for anomaly detection
        
        :param df: DataFrame of network traffic
        :return: Preprocessed feature matrix
        """
        # Convert categorical features
        df['source_ip_encoded'] = pd.Categorical(df['source_ip']).codes
        df['destination_ip_encoded'] = pd.Categorical(df['destination_ip']).codes
        df['protocol_encoded'] = pd.Categorical(df['protocol']).codes
        
        # Select features for anomaly detection
        features = ['packet_length', 'source_ip_encoded', 
                    'destination_ip_encoded', 'protocol_encoded']
        
        # Scale features
        scaler = StandardScaler()
        return scaler.fit_transform(df[features])
    
    def detect_anomalies(self, X):
        """
        Detect network traffic anomalies using Isolation Forest
        
        :param X: Preprocessed feature matrix
        :return: Anomaly labels
        """
        clf = IsolationForest(contamination=0.1, random_state=42)
        y_pred = clf.fit_predict(X)
        return y_pred
    
    def run_analysis(self):
        """
        Complete network traffic analysis workflow
        """
        # Capture network traffic
        df = self.capture_network_traffic()
        
        # Preprocess data
        X = self.preprocess_data(df)
        
        # Detect anomalies
        anomaly_labels = self.detect_anomalies(X)
        
        # Mark anomalies in original dataframe
        df['is_anomaly'] = anomaly_labels == -1
        self.anomalies = df[df['is_anomaly']]
        
        return df, self.anomalies
    
class TrafficDashboard:
    def __init__(self, analyzer):
        """
        Initialize Dash web dashboard for traffic visualization
        
        :param analyzer: NetworkTrafficAnalyzer instance
        """
        self.analyzer = analyzer
        self.app = dash.Dash(__name__)
        self.setup_layout()
    
    def setup_layout(self):
        """
        Create dashboard layout
        """
        self.app.layout = html.Div([
            html.H1('Network Traffic Analysis Dashboard'),
            
            dcc.Graph(id='traffic-volume-graph'),
            dcc.Graph(id='anomaly-distribution-graph'),
            
            dcc.Interval(
                id='interval-component',
                interval=60*1000,  # Update every minute
                n_intervals=0
            )
        ])
        
        @self.app.callback(
            [Output('traffic-volume-graph', 'figure'),
             Output('anomaly-distribution-graph', 'figure')],
            [Input('interval-component', 'n_intervals')]
        )
        def update_graphs(n):
            # Run analysis
            df, anomalies = self.analyzer.run_analysis()
            
            # Traffic Volume Graph
            traffic_volume = px.line(
                df.groupby('timestamp')['packet_length'].sum().reset_index(), 
                x='timestamp', 
                y='packet_length', 
                title='Network Traffic Volume'
            )
            
            # Anomaly Distribution Graph
            anomaly_dist = px.scatter(
                anomalies, 
                x='source_ip', 
                y='packet_length', 
                color='protocol',
                title='Network Anomalies'
            )
            
            return traffic_volume, anomaly_dist
    
    def run(self, port=8050):
        """
        Run the Dash web application
        
        :param port: Port to run the dashboard on
        """
        self.app.run_server(debug=True, port=port)

def main():
    # Initialize network traffic analyzer
    analyzer = NetworkTrafficAnalyzer(interface='eth0', capture_duration=60)
    
    # Create dashboard
    dashboard = TrafficDashboard(analyzer)
    
    # Run dashboard in a separate thread
    dashboard_thread = threading.Thread(target=dashboard.run)
    dashboard_thread.start()

if __name__ == "__main__":
    main()
