import json
import webbrowser
from pyvis.network import Network


def chart():
# Your JSON data
    json_file = r"C:\Users\DELL\Downloads\python_app-Copy\json_file\packet_data.json"
    with open(json_file) as f:
            lines = f.readlines()

    # Create a network graph
    graph = Network(notebook=True)

    # Iterate through JSON data and add nodes and edges
    for line in lines:
        if "IP" in line and not "IPv6" in line:
            nodes = line.split(" > ")
            for i in range(len(nodes) - 1):
                src, dest = nodes[i], nodes[i + 1]
                graph.add_node(src)
                graph.add_node(dest)
                graph.add_edge(src, dest)


    file_path=r'chart\graph.html'
    # Save the graph to an HTML file
    graph.show(file_path)
    webbrowser.open(r'C:\Users\DELL\Downloads\python_app-Copy\chart\graph.html')
    
#chart()