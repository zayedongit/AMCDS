// AMCDS Neo4j Graph Schema
// Run via: cat init.cypher | cypher-shell -u neo4j -p amcds_graph_2024

// Constraints
CREATE CONSTRAINT host_id IF NOT EXISTS FOR (h:Host) REQUIRE h.id IS UNIQUE;
CREATE CONSTRAINT user_id IF NOT EXISTS FOR (u:User) REQUIRE u.id IS UNIQUE;
CREATE CONSTRAINT service_id IF NOT EXISTS FOR (s:Service) REQUIRE s.id IS UNIQUE;
CREATE CONSTRAINT subnet_id IF NOT EXISTS FOR (sn:Subnet) REQUIRE sn.id IS UNIQUE;
CREATE CONSTRAINT incident_id IF NOT EXISTS FOR (i:Incident) REQUIRE i.id IS UNIQUE;
CREATE CONSTRAINT alert_id IF NOT EXISTS FOR (a:Alert) REQUIRE a.id IS UNIQUE;

// Indexes
CREATE INDEX host_ip IF NOT EXISTS FOR (h:Host) ON (h.ip_address);
CREATE INDEX user_dept IF NOT EXISTS FOR (u:User) ON (u.department);
CREATE INDEX incident_status IF NOT EXISTS FOR (i:Incident) ON (i.status);
CREATE INDEX alert_type IF NOT EXISTS FOR (a:Alert) ON (a.alert_type);
