import networkx as nx
from typing import List, Tuple
from datetime import datetime

class GraphStore:
    def __init__(self):
        self.g = nx.MultiDiGraph()
        
    def add_email_node(self, uid: int, subject: str, timestamp: str):
        self.g.add_node(f"email_{uid}", type="email", subject=subject, timestamp=timestamp)
        
    def add_sender_node(self, email_address: str):
        self.g.add_node(f"sender_{email_address}", type="sender", address=email_address)
        
    def add_url_node(self, url: str, domain: str):
        self.g.add_node(f"url_{url}", type="url", url=url, domain=domain)
        
    def add_domain_node(self, domain: str):
        self.g.add_node(f"domain_{domain}", type="domain", domain=domain)
        
    def add_link(self, source: str, target: str, rel_type: str):
        self.g.add_edge(source, target, type=rel_type)

    def process_parsed_email(self, uid: int, parsed):
        self.add_email_node(uid, parsed.subject, datetime.utcnow().isoformat())
        self.add_sender_node(parsed.from_addr)
        self.add_link(f"sender_{parsed.from_addr}", f"email_{uid}", "SENT")
        
        for url_info in parsed.urls:
            self.add_url_node(url_info.normalized, url_info.domain)
            self.add_domain_node(url_info.domain)
            self.add_link(f"email_{uid}", f"url_{url_info.normalized}", "CONTAINS")
            self.add_link(f"url_{url_info.normalized}", f"domain_{url_info.domain}", "HOSTED_ON")
            
    def get_email_subgraph(self, uid: int, radius: int = 2) -> nx.MultiDiGraph:
        if f"email_{uid}" not in self.g:
            return nx.MultiDiGraph()
        # Simplistic ego graph for demo
        return nx.ego_graph(self.g, f"email_{uid}", radius=radius, undirected=True)

# Singleton
graph_store = GraphStore()
