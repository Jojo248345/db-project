CREATE TABLE Kunden (
    Kunden_id INT AUTO_INCREMENT PRIMARY KEY,
    Kunden_password VARCHAR(15) NOT NULL,
    Kunden_Adresse VARCHAR(50) NOT NULL,
    Kunden_Name VARCHAR(30) NOT NULL,
    Kunden_Vorname VARCHAR(30) NOT NULL,
    Kunden_Benutzername VARCHAR(15) NOT NULL
);

CREATE TABLE MitarbeiterInnen (
    MitarbeiterInnen_id INT AUTO_INCREMENT PRIMARY KEY,
    MitarbeiterInnen_Name VARCHAR(30) NOT NULL,
    MitarbeiterInnen_Vorname VARCHAR(30) NOT NULL,
    MitarbeiterInnen_Aufgabe VARCHAR(100) NOT NULL
);

CREATE TABLE Drohnen (
    Drohnen_id INT AUTO_INCREMENT PRIMARY KEY,
    Drohnen_Name VARCHAR(20) NOT NULL,
    Drohnen_Geschwindigkeit_km/h INT NOT NULL,
    Drohnen_beschäftigt Boolean NOT NULL
);

CREATE TABLE Produkte (
    Produkt_id INT AUTO_INCREMENT PRIMARY KEY,
    Produkt_Name VARCHAR(30),
    Produkt_Preis_CHF Float NOT NULL,
    Foreign Key (Rezept_id) REFERENCES Rezept_id
);

CREATE TABLE Rezept (
    Rezept_id INT AUTO_INCREMENT PRIMARY KEY,
    Mehl_g Float NOT NULL,
    Wasser_ml Float NOT NULL,
    Butter_g Float NOT NULL,
    Milch_ml Float NOT NULL,
    Eier_stk Float NOT NULL,
    Zucker_g Float NOT NULL,
    Salz_g Float NOT NULL,
    Schokolade_g Float NOT NULL,
);
 CREATE TABLE Bestellung (
    Bestellung_id INT AUTO_INCREMENT PRIMARY KEY,
    Foreign KEY (Produkt_id) REFERENCES Produkt_id,
    FOREIGN KEY (Kunden_id) REFERENCES Kunden_id
 )

 CREATE TABLE Website (
    Website_URL INT AUTO_INCREMENT PRIMARY KEY,
    Website_Werbung VARCHAR(200)
 );