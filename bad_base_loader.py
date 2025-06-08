# criar_base_rag.py
import os
from chromadb.utils.embedding_functions import SentenceTransformerEmbeddingFunction
import chromadb

class BadBaseLoader:
    def __init__(self, base_dir="badbase"):
        self.base_dir = base_dir
        self.client = chromadb.Client()
        self.embedding_function = SentenceTransformerEmbeddingFunction()
        self.load_collections()

    def read_code_blocks(self, filepath):
        with open(filepath, "r", encoding="utf-8") as f:
            content = f.read()
            blocks = [block.strip() for block in content.split("--valknut--satty--") if block.strip()]
        return blocks

    def load_collections(self):
        for filename in os.listdir(self.base_dir):
            if filename.endswith(".txt"):
                filepath = os.path.join(self.base_dir, filename)
                code_blocks = self.read_code_blocks(filepath)
                collection_name = os.path.splitext(filename)[0]
                collection = self.client.get_or_create_collection(
                    collection_name,
                    embedding_function=self.embedding_function
                )
                for i, block in enumerate(code_blocks):
                    collection.add(documents=[block], ids=[f"{collection_name}_{i}"])

    def get_client(self):
        return self.client
