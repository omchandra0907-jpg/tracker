import os
import json
from dotenv import load_dotenv
from neo4j import GraphDatabase

load_dotenv()

URI = os.getenv("NEO4J_URI")
USERNAME = os.getenv("NEO4J_USERNAME")
PASSWORD = os.getenv("NEO4J_PASSWORD")

def seed_database():
    if not URI or not PASSWORD:
        print("❌ Error: Missing Neo4j credentials in .env file.")
        return

    driver = GraphDatabase.driver(URI, auth=(USERNAME, PASSWORD))
    with open("osint_db.json", "r") as f: osint_data = json.load(f)

    with driver.session() as session:
        session.run("MATCH (n) DETACH DELETE n")
        for actor in osint_data:
            session.run("MERGE (a:Actor {name: $real_name}) SET a.alias = $surface_alias, a.platform = $platform", **actor)
            for w in actor.get("known_wallets", []):
                session.run("MATCH (a:Actor {name: $name}) MERGE (w:Wallet {address: $wallet}) MERGE (a)-[:OWNS_WALLET]->(w)", name=actor["real_name"], wallet=w)
            for em in actor.get("known_emails", []):
                session.run("MATCH (a:Actor {name: $name}) MERGE (e:Email {address: $email}) MERGE (a)-[:USES_EMAIL]->(e)", name=actor["real_name"], email=em)
            for cm in actor.get("known_comms", []):
                session.run("MATCH (a:Actor {name: $name}) MERGE (c:Comms {handle: $comm}) MERGE (a)-[:USES_COMMS]->(c)", name=actor["real_name"], comm=cm)
            for on in actor.get("known_onions", []):
                session.run("MATCH (a:Actor {name: $name}) MERGE (o:Infrastructure {domain: $onion}) MERGE (a)-[:OWNS_INFRA]->(o)", name=actor["real_name"], onion=on)
            for sl in actor.get("stylometry_markers", []):
                session.run("MATCH (a:Actor {name: $name}) MERGE (s:Slang {term: $slang}) MERGE (a)-[:KNOWN_SLANG]->(s)", name=actor["real_name"], slang=sl.lower())

    print("\n✅ Neo4j Database seeded with all 25 Advanced Profiles!")
    driver.close()

if __name__ == "__main__":
    seed_database()
