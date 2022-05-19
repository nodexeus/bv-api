-- Add up migration script here

ALTER TABLE blockchains ADD COLUMN token TEXT;

UPDATE blockchains SET token = 'HNT' WHERE name = 'Helium';

UPDATE blockchains SET token = 'ETH' WHERE name = 'Ehterium 2.0';

UPDATE blockchains SET token = 'BTC' WHERE name = 'Bitcoin';

UPDATE
	blockchains
SET
	token = 'POKT',
	name = 'Pocket'
WHERE
	name = 'Pockt Networks';

UPDATE blockchains SET token = 'SOL' WHERE name = 'Solana';

UPDATE blockchains SET token = 'ALGO' WHERE name = 'Algorand';

UPDATE
	blockchains
SET
	token = 'AVAX',
	name = 'Avalanch'
WHERE
	name = 'Avax';