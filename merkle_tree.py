import hashlib
from typing import List, Dict, Union
import matplotlib.pyplot as plt
import networkx as nx

class MerkleTree:
    def __init__(self, leaves: List[bytes]):
        if not leaves:
            raise ValueError("Cannot create a Merkle tree with no leaves")

        self.leaves = [leaf for leaf in leaves]
        self.tree = self._build_tree(self.leaves)

    def _hash_pair(self, left: bytes, right: bytes) -> bytes:
        """Hash a pair of nodes to create their parent"""
        # Concatenate and hash
        combined = left + right
        return hashlib.sha256(combined).digest()

    def _build_tree(self, nodes: List[bytes]) -> List[List[bytes]]:
        """Build the complete Merkle tree from leaves to root"""
        # Start with the leaves as the first level
        tree = [nodes]

        # Continue until we reach the root
        while len(nodes) > 1:
            # Create parent level
            parent_level = []

            # Process pairs of nodes
            for i in range(0, len(nodes), 2):
                # If this is the last node and has no pair, duplicate it
                if i + 1 >= len(nodes):
                    parent = self._hash_pair(nodes[i], nodes[i])
                else:
                    parent = self._hash_pair(nodes[i], nodes[i + 1])

                parent_level.append(parent)

            # Add this level to the tree
            tree.append(parent_level)

            # Move up to the next level
            nodes = parent_level

        return tree

    def get_root(self) -> bytes:
        return self.tree[-1][0]

    def get_proof(self, leaf: bytes) -> List[Dict[str, Union[bytes, str]]]:
        """
        Generate a Merkle proof for a leaf
        Returns a list of steps, each with a sibling hash and position ('left' or 'right')
        """
        # Find leaf index
        try:
            leaf_index = self.leaves.index(leaf)
        except ValueError:
            raise ValueError("Leaf not found in the tree")

        proof = []
        node_index = leaf_index

        # Start from the leaf level and go up
        for level in range(len(self.tree) - 1):
            current_level = self.tree[level]

            # Determine if this node is left or right in its pair
            is_right = node_index % 2 == 1

            # Get the sibling index
            if is_right:
                sibling_index = node_index - 1
                position = "left"
            else:
                sibling_index = node_index + 1
                position = "right"

            # Handle odd-sized levels by duplicating the last node
            if sibling_index >= len(current_level):
                sibling = current_level[node_index]
            else:
                sibling = current_level[sibling_index]


            proof.append({
                    "data": sibling,
                    "position": position
                })

            # Move to the parent index for the next level
            node_index = node_index // 2

        return proof

    def visualize(self, save_path: str = None, show: bool = True, labels: Dict = None) -> None:
        """
        Visualize the Merkle tree using NetworkX and Matplotlib

        Args:
            save_path: Optional path to save the visualization
            show: Whether to display the visualization
            labels: Optional dictionary mapping node hex values to readable labels
        """
        # Create a directed graph
        G = nx.DiGraph()

        # Track node positions for layout
        pos = {}

        # Add nodes and edges
        y_offset = 0
        node_id_counter = 0
        node_mappings = {}  # Map bytes to node IDs

        # Process each level from root to leaves (reversed)
        for level_idx, level in reversed(list(enumerate(self.tree))):
            x_spacing = 1.0 / (len(level) + 1)

            for i, node in enumerate(level):
                # Create a unique node ID
                node_id = f"node_{node_id_counter}"
                node_id_counter += 1

                # Map this node's bytes to its ID
                node_mappings[node.hex()] = node_id

                # Add node to graph
                node_label = None
                if labels and node.hex() in labels:
                    node_label = labels[node.hex()]
                else:
                    # Use truncated hash for display
                    node_label = node.hex()[:8] + "..."

                # For leaf nodes, add additional information if available
                if level_idx == 0:  # This is a leaf level
                    G.add_node(node_id, label=node_label, is_leaf=True)
                else:
                    G.add_node(node_id, label=node_label, is_leaf=False)

                # Position the node
                x_pos = (i + 1) * x_spacing
                pos[node_id] = (x_pos, -level_idx)  # Negative Y for top-down layout

                # If not at root level, add edges to parent
                if level_idx < len(self.tree) - 1:
                    parent_level = self.tree[level_idx + 1]
                    parent_idx = i // 2
                    if parent_idx < len(parent_level):
                        parent = parent_level[parent_idx]
                        parent_id = node_mappings[parent.hex()]
                        G.add_edge(parent_id, node_id)

        # Create plot
        plt.figure(figsize=(12, 8))

        # Draw nodes
        leaf_nodes = [n for n, attrs in G.nodes(data=True) if attrs.get('is_leaf', False)]
        non_leaf_nodes = [n for n, attrs in G.nodes(data=True) if not attrs.get('is_leaf', False)]

        # Draw non-leaf nodes
        nx.draw_networkx_nodes(G, pos,
                               nodelist=non_leaf_nodes,
                               node_color='lightblue',
                               node_size=1000,
                               alpha=0.8)

        # Draw leaf nodes with different color
        nx.draw_networkx_nodes(G, pos,
                               nodelist=leaf_nodes,
                               node_color='lightgreen',
                               node_size=1000,
                               alpha=0.8)

        # Draw edges
        nx.draw_networkx_edges(G, pos, width=2, alpha=0.5, edge_color='gray')

        # Draw labels
        labels = {node: G.nodes[node]['label'] for node in G.nodes()}
        nx.draw_networkx_labels(G, pos, labels=labels, font_size=8)

        # Set title and adjust layout
        plt.title("Merkle Tree Visualization")
        plt.axis('off')
        plt.tight_layout()

        # Save if path is provided
        if save_path:
            plt.savefig(save_path, dpi=300, bbox_inches='tight')
            print(f"Visualization saved to {save_path}")

        # Show plot if requested
        if show:
            plt.show()
        else:
            plt.close()
