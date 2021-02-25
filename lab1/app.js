const crypto = require('crypto');
const blake2 = require('blake2');
const bcrypt = require('bcrypt');

const studentId = '20173700';

const sha256x3 = (studentId) => {
	const sha1x = crypto.createHash('sha256').update(studentId).digest('hex');
	const shax2 = crypto.createHash('sha256').update(sha1x).digest('hex');
	
	return crypto.createHash('sha256').update(shax2).digest('hex');
}

const sha256x5 = (studentId) => {
	const sha256x3New = sha256x3(studentId);
	const shax4 = crypto.createHash('sha256').update(sha256x3New).digest('hex');
	
	return crypto.createHash('sha256').update(shax4).digest('hex');
}

const md5sha256 = (studentId) => {
	const md5 = crypto.createHash('md5').update(studentId).digest('hex');
	const sha256 = crypto.createHash('sha256').update(md5).digest('hex');
	
	return crypto.createHash('sha256').update(sha256).digest('hex');
}

const sha256blake2s = (studentId) => {
	const sha256 = crypto.createHash('sha256').update(studentId).digest('hex');
	
	return blake2.createHash('blake2s').update(Buffer.from(sha256)).digest('hex');
}

const sha256blake2b = (studentId) => {
	const sha256 = crypto.createHash('sha256').update(studentId).digest('hex');
	
	return blake2.createHash('blake2b').update(Buffer.from(sha256)).digest('hex');
}

const sha256blakeb2blake2s = (studentId) => {
	const sha256blake2 = sha256blake2s(studentId);
	
	return blake2.createHash('blake2s').update(Buffer.from(sha256blake2)).digest('hex');
}

const md5blake2s = (studentId) => {
	const md5 = crypto.createHash('md5').update(studentId).digest('hex');
	
	return blake2.createHash('blake2s').update(Buffer.from(md5)).digest('hex');
}

const md5Blake2sx2blake2b = (studentId) => {
	const md5Blake2sx2 = md5blake2s(studentId);
	
	return blake2.createHash('blake2s').update(Buffer.from(md5Blake2sx2)).digest('hex');
}

const blowfishSalt10 = (studentId) => {
	const saltRounds = 10;
	const hash = bcrypt.hashSync(studentId, saltRounds);
	
	return hash;
}

const blowfishSalt10x2BlowfishSalt15 = (studentId) => {
	const blowfishSalt10x2 = blowfishSalt10(studentId);
	const saltRounds = 15;
	const hash = bcrypt.hashSync(blowfishSalt10x2, saltRounds);
	
	return hash;
}

console.log(`Sha256 x 3: ${sha256x3(studentId)}`);
console.log(`Sha256 x 5: ${sha256x5(studentId)}`);
console.log(`Sha256 x md5: ${md5sha256(studentId)}`);
console.log(`Sha256 x blake2s: ${sha256blake2s(studentId)}`);
console.log(`Sha256 x blake2b: ${sha256blake2b(studentId)}`);
console.log(`Sha256 x blake2b x blake2s: ${sha256blakeb2blake2s(studentId)}`);
console.log(`md5 x blake2s: ${md5blake2s(studentId)}`);
console.log(`md5 x blake2s 2x x blake2b${md5Blake2sx2blake2b(studentId)}`);
console.log(`blowfish x salt10${blowfishSalt10(studentId)}`);
console.log(`blowfishSalt10x2 x blowfishSalt15: ${blowfishSalt10x2BlowfishSalt15(studentId)}`);
