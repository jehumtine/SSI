import matplotlib.pyplot as plt
from pathlib import Path

from zk_merkle_identity import ZKMerkleIdentity


class IdentityVisualizer:
    """Helper class for advanced visualization of ZK Merkle Identity"""

    @staticmethod
    def create_document_visualization(identity: ZKMerkleIdentity, save_dir: str, show: bool = False) -> None:
        """
        Create visualizations for the identity including:
        1. The Merkle tree structure
        2. Document relationships
        3. Document attributes

        Args:
            identity: The ZKMerkleIdentity instance
            save_dir: Directory to save visualizations
            show: Whether to display the visualizations
        """
        # Create directory if it doesn't exist
        save_dir = Path(save_dir)
        save_dir.mkdir(exist_ok=True, parents=True)

        # 1. Create Merkle tree visualization
        if identity.merkle_tree:
            # Create readable labels for commitments
            labels = {}
            for commitment_hex, data in identity.salt_cache.items():
                if "document_id" in data:
                    labels[commitment_hex] = data["document_id"]

            # Generate and save tree visualization
            tree_path = save_dir / "merkle_tree.png"
            identity.merkle_tree.visualize(
                save_path=str(tree_path),
                show=show,
                labels=labels
            )

            # 2. Create document attribute visualization
            plt.figure(figsize=(12, 6))

            # Collect document IDs and their attributes
            docs = {}
            for commitment_hex, data in identity.salt_cache.items():
                if "document_id" in data:
                    doc_id = data["document_id"]
                    if doc_id not in docs:
                        docs[doc_id] = set()
                    if "attributes" in data:
                        docs[doc_id].update(data["attributes"])

            # Plot as a horizontal bar chart
            if docs:
                fig, ax = plt.subplots(figsize=(12, 8))

                # Process each document
                y_positions = []
                y_labels = []
                colors = []

                all_attrs = set()
                for doc_id, attrs in docs.items():
                    all_attrs.update(attrs)

                # Sort attributes for consistency
                all_attrs = sorted(all_attrs)

                # Create a matrix for the visualization
                attr_matrix = []
                doc_ids = sorted(docs.keys())

                for doc_id in doc_ids:
                    doc_attrs = docs[doc_id]
                    attr_row = [1 if attr in doc_attrs else 0 for attr in all_attrs]
                    attr_matrix.append(attr_row)

                # Create heatmap
                im = ax.imshow(attr_matrix, cmap='Blues', aspect='auto')

                # Set labels
                ax.set_yticks(range(len(doc_ids)))
                ax.set_yticklabels(doc_ids)
                ax.set_xticks(range(len(all_attrs)))
                ax.set_xticklabels(all_attrs, rotation=45, ha='right')

                # Add colorbar
                cbar = ax.figure.colorbar(im, ax=ax)
                cbar.ax.set_ylabel("Included in Document", rotation=-90, va="bottom")

                # Set title
                plt.title("Document Attributes in ZK Merkle Identity")
                plt.tight_layout()

                # Save the visualization
                attrs_path = save_dir / "document_attributes.png"
                plt.savefig(attrs_path, dpi=300, bbox_inches='tight')
                print(f"Document attributes visualization saved to {attrs_path}")

                if show:
                    plt.show()
                else:
                    plt.close()
