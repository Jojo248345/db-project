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
    Drohnen_Geschwindigkeit_kmh INT NOT NULL,
    Drohnen_Preis_CHF FLOAT NOT NULL,
    Drohnen_beschaeftigt BOOLEAN NOT NULL
);

CREATE TABLE Produkte (
    Produkt_id INT AUTO_INCREMENT PRIMARY KEY,
    Produkt_Name VARCHAR(30) NOT NULL,
    Produkt_Preis_CHF FLOAT NOT NULL,
    Rezept_id INT,
    FOREIGN KEY (Rezept_id) REFERENCES Rezept(Rezept_id)
);

CREATE TABLE Rezept (
    Rezept_id INT AUTO_INCREMENT PRIMARY KEY,
    Mehl_g FLOAT NOT NULL,
    Wasser_ml FLOAT NOT NULL,
    Butter_g FLOAT NOT NULL,
    Milch_ml FLOAT NOT NULL,
    Eier_stk FLOAT NOT NULL,
    Zucker_g FLOAT NOT NULL,
    Salz_g FLOAT NOT NULL,
    Schokolade_g FLOAT NOT NULL
);
 CREATE TABLE Bestellung (
    Bestellung_id INT AUTO_INCREMENT PRIMARY KEY,
    Kunden_id INT NOT NULL,
    Drohnen_id INT NOT NULL,
    Bestell_Datum DATETIME,
    Gesamtpreis_CHF FLOAT,
    Status VARCHAR(20),
    FOREIGN KEY (Kunden_id) REFERENCES Kunden(id),
    FOREIGN KEY (Drohnen_id) REFERENCES Drohnen(Drohnen_id)
);

 INSERT INTO Rezept 
(Mehl_g, Wasser_ml, Butter_g, Milch_ml, Eier_stk, Zucker_g, Salz_g, Schokolade_g)
VALUES (200, 100, 50, 50, 2, 30, 5, 20);
INSERT INTO MitarbeiterInnen (MitarbeiterInnen_Name, MitarbeiterInnen_Vorname, MitarbeiterInnen_Aufgabe) 
VALUES ('Joris', 'Struve','Chef');
