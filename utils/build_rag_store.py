from pathlib import Path
import chromadb
import requests


OLLAMA_BASE_URL = "http://localhost:11434"
EMBED_MODEL = "embeddinggemma"
CHROMA_PATH = "chroma_db"
COLLECTION_NAME = "sentinelops_knowledge"


def get_embedding(text: str) -> list[float]:
    response = requests.post(
        f"{OLLAMA_BASE_URL}/api/embeddings",
        json={
            "model": EMBED_MODEL,
            "prompt": text,
        },
        timeout=60,
    )
    response.raise_for_status()
    data = response.json()
    return data["embedding"]


def read_docs(folder: str) -> list[tuple[str, str]]:
    docs = []
    for path in sorted(Path(folder).glob("*.txt")):
        docs.append((path.stem, path.read_text(encoding="utf-8")))
    return docs


def main() -> None:
    client = chromadb.PersistentClient(path=CHROMA_PATH)
    collection = client.get_or_create_collection(name=COLLECTION_NAME)

    docs = read_docs("knowledge_base")
    if not docs:
        print("No knowledge base files found.")
        return

    ids = []
    documents = []
    embeddings = []
    metadatas = []

    for doc_id, content in docs:
        ids.append(doc_id)
        documents.append(content)
        embeddings.append(get_embedding(content))
        metadatas.append({"source": f"{doc_id}.txt"})

    existing = collection.get()
    if existing and existing.get("ids"):
        collection.delete(ids=existing["ids"])

    collection.add(
        ids=ids,
        documents=documents,
        embeddings=embeddings,
        metadatas=metadatas,
    )

    print(f"Indexed {len(ids)} knowledge base documents into Chroma.")


if __name__ == "__main__":
    main()