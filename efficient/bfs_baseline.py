from collections import deque

def run_bfs(graph, start_node):
    """Classic BFS template for comparison"""
    visited = set()
    queue = deque([start_node])
    visited.add(start_node)
    
    while queue:
        vertex = queue.popleft()
        
        for neighbor in graph[vertex]:
            if neighbor not in visited:
                visited.add(neighbor)
                queue.append(neighbor)
    return visited
