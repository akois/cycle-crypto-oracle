import Cycle from '@cycle/core';
import {div, button, h1, h4, a, makeDOMDriver, section, label, input, ul, li} from '@cycle/dom';
import {makeHTTPDriver} from '@cycle/http';
import { Observable } from 'rx';

const containerStyle = {
  background: '#EFEFEF',
  padding: '5px',
}

const sectionStyle = {
  marginBottom: '10px',
}

const searchLabelStyle = {
  display: 'inline-block',
  width: '100px',
  textAlign: 'right',
}

const comboBoxStyle = {
  position: 'relative',
  display: 'inline-block',
  width: '300px',
}

const inputTextStyle = {
  padding: '5px',
}


function hex2string(bytes) {
  var str = ''

  for (var i=0; i < bytes.length; ++i)
  {
    var chr = bytes[i].toString(16)
    str += chr.length < 2 ? '0' + chr : chr
  }
  return str;
}

function string2hex(str) {
    var bytes = [];
    
	for(var i=0; i< str.length-1; i+=2){
		bytes.push(parseInt(str.substr(i, 2), 16));
	}
    return bytes;
}

//str = String.fromCharCode.apply(String, bytes);

function main(sources) {

   const USERS_URL = 'http://babaj.tales.sen.symantec.com/CryptoService/OracleService.svc/Decrypt?mode=ErrorsInBody&cipher=5665727952616e646f6d495631323334ab30cdf1e3fbc97c41c1e44cb22e33ed40bff4855d03ea9bd4ad8624720be65';
 
  //5665727952616e646f6d495631323334ab30cdf1e3fbc97c41c1e44cb22e33ed40bff4855d03ea9bd4ad8624720be657
  //const timer$ = Observable.timer(0, 5000)//.publish();
  
  const cipher$=sources.DOM.select('.cipher').events('input')
	.map(ev => ev.target.value)
	.startWith('');
  
  const cipher_state$=cipher$
  	.map (cipher => (cipher.length >= 64 && cipher.length%16==0))

  const running_state$=Observable.just (false);

  
  function zip_blocks (blocks)
  {
	var finalBlock=new Array(16);
	
	for (var i=0; i < blocks.length; ++i)
	{
		for (var j=0; j < 16; ++j)
			finalBlock[j] ^= blocks[i][j];
	}
	return finalBlock;
  }

  
  function get_candidates (originalIV, cipher, lastIV)
  {
	//get index
	var i;
	
	for (i=0; i < 16 && originalIV[i] != lastIV[i]; ++i);
	
	var acc=zip_blocks ([originalIV, lastIV]);
	
	if (i==0) return {completed: true, candidates: []};
	
	var index=i-1;
	
	var _candidates=[];
	
	return {completed: false, candidates: _candidates};
  }
   
  const decrypt_cipher$ = sources.DOM.select('.start_decrypt').events('click')
	.withLatestFrom (cipher$, (evt,cipher)=>cipher)
	.map (cipherblock=>{
	
		var cipherBlocks = {};
		
		for(var i = 0, blockCount=cipherblock.length/32-1; i < blockCount; i++) 
		{
			var cipherStr=cipherblock.substring (32*(i+1), 32*(i+2));
			
			var IV=string2hex(cipherblock.substring (32*i, 32*(i+1)));
			var cipher=string2hex(cipherStr);
			
			cipherBlocks[cipherStr]=function (newIV) {
				return get_candidates(IV, cipher, newIV);
			};
		}
		return cipherBlocks;
	})
	.startWith({});
	
    /*.scan (seconds=>++seconds, 1)
    //.map(a => {return {url: USERS_URL + String(a), method: 'GET'};})

    //.selectMany (a => Rx.Observable.just(1).map(a => {return {url: USERS_URL + String(a), method: 'GET'};}));
    .selectMany (a => Observable.range(10, 5))
    .map(a => {return {url: USERS_URL, method: 'GET'};})*/
    
 

  const user$ = sources.HTTP
    .filter(res$ => res$.request.url.indexOf(USERS_URL) === 0)
    .mergeAll()
    .map(res => {alert (res.text); return res.text;})
    .startWith(null);

  const vtree$ = Observable.combineLatest(cipher_state$, running_state$, decrypt_cipher$,
	  (cipher_state, running_state, decrypt_cipher) =>
      div('.decryption', {style: containerStyle}, [
		section({style: sectionStyle}, [
		  label({style: searchLabelStyle}, 'cipher:'),
		  input('.cipher', {type: 'text', style: inputTextStyle}),
		  button('.start_decrypt', {disabled: !cipher_state}, 'Start')
		]),
        ul({className: 'search-results'}, Object.keys(decrypt_cipher).map(result =>
          li({className: 'search-result'}, [
			label({style: searchLabelStyle}, result)
          ])
        ))
		
      ])
    );
  

  return {
    DOM: vtree$,
    //HTTP: getRandomUser$
  };
}

Cycle.run(main, {
  DOM: makeDOMDriver('#main-container'),
  HTTP: makeHTTPDriver()
});
