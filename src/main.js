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

function hex2Message (hex)
{
	var trimMsg=[];
	
	for (var i=0; i < hex.length; ++i)
	{
		if (hex[i] !== 0)
			trimMsg.push(hex[i]);
	}
		
	return String.fromCharCode.apply(String, trimMsg);
}

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


function main(sources) {

   const USERS_URL = 'http://babaj.tales.sen.symantec.com/CryptoService/OracleService.svc/Decrypt?mode=ErrorsInBody&cipher=';
   
 
  //5665727952616e646f6d495631323334ab30cdf1e3fbc97c41c1e44cb22e33ed40bff4855d03ea9bd4ad8624720be657
  //const timer$ = Observable.timer(0, 5000)//.publish();
  
  const cipher$=sources.DOM.select('.cipher').events('input')
	.map(ev => ev.target.value)
	.startWith('');
  
  const cipher_state$=cipher$
  	.map (cipher => (cipher.length >= 64 && cipher.length%16==0))

  const running_state$=Observable.just (false);

  
    
  function get_candidates (originalIV, cipher, lastIV)
  {
	//get index
	if (lastIV == null) lastIV=originalIV;
	
	var index=0;
	
	for (index=0; index < 16 && originalIV[index] == lastIV[index]; ++index);

	var zeroBlock=Array.apply(null, Array(16)).map(() => 0);
	var padBlock=zeroBlock.slice();
	for (var i=index; i < 16; ++i) padBlock[i]=(16-index);
	
	var acc=zip_blocks ([originalIV, lastIV, padBlock]);
	
	//newIV=IV ^ pads ^ acc ^ idxl
	
	if (index===0) return {completed: true, candidates: [], result: acc, key: hex2string(cipher)};
	
	index=index-1;
	
	//special case for padding
	//todo this will work only for text messages
	if (index===14 && acc[15] < 16)
	{
		index=15-acc[15];
		acc=zeroBlock.slice();
		
		for (var i=index; i < 16; ++i) acc[i]=15-index;
	}
	
	//1..128
	var _candidates=Array.apply(null, Array(127))
		.map((_, i) => i+1)
		.map (char =>{
			var newPadBlock=zeroBlock.slice();
			for (var i=index; i < 16; ++i) newPadBlock[i]=(16-index);
			
			var newAcc=acc.slice();
			newAcc[index]=char;
			
			return zip_blocks ([originalIV, newAcc, newPadBlock]).concat(cipher);
		});
		
	return {completed: false, candidates: _candidates, result: acc, key: hex2string(cipher)};
  }
   
   
   function getCurriedFunction (IV, cipher)
   {
		var ivc=IV.slice();
		var cc=cipher.slice();
		
		return function (newIV) {
				return get_candidates(ivc, cc, newIV);
			};
   }
   
  const cipherblock_dicrtionary$ = sources.DOM.select('.start_decrypt').events('click')
	.withLatestFrom (cipher$, (evt,cipher)=>cipher)
	.map (cipherblock=>{
	
		var cipherBlocks = {};
		
		for(var i = 0, blockCount=cipherblock.length/32-1; i < blockCount; i++) 
		{
			var cipherStr=cipherblock.substring (32*(i+1), 32*(i+2));
			
			var IV=string2hex(cipherblock.substring (32*i, 32*(i+1)));
			var cipher=string2hex(cipherStr);
			
			cipherBlocks[cipherStr]=getCurriedFunction (IV, cipher);
		}
		return cipherBlocks;
	})
	

	const http_response$ = sources.HTTP
		.filter(res$ => res$.request.url.indexOf(USERS_URL) === 0)
		.mergeAll()
		.filter (res=>res.text.indexOf('Invalid Padding') > 0)
		.map(res => {
			var idx=res.req.url.indexOf('cipher=');
			return {IV: res.req.url.substring (idx+7, idx+7+32), cipher: res.req.url.substring (idx+7+32, idx+7+32+32)};
		})

	
	const scan_result$=http_response$
		.startWith (null);
	
	const scan_status$=Observable.combineLatest (cipherblock_dicrtionary$, scan_result$,
		(dict, scan_result)=>{
			if (scan_result==null)
				return Object.keys(dict).map (key=>dict[key](null));
			else
				return [dict[scan_result.cipher](string2hex(scan_result.IV))];
		}
	)
	.flatMap (status=>Observable.from (status));


	const scan_request$=scan_status$
		.map (status=>status.candidates);
		
	const scan_progres$=scan_status$
		.scan ((acc, status)=>{ //todo rework
				if (!(status.key===undefined || status.result===undefined))
				{
					acc[status.key]=hex2string(status.result);
				}
					
				return acc;
			}, ({}))
		.startWith ({});
		
	const httpRequest$=scan_request$
		.flatMap (candidates=>
			Observable.from (candidates.map (cipherblock=>{
				return {url: USERS_URL+hex2string(cipherblock), method: 'GET'};}))
		);
   
  
  const vtree$ = Observable.combineLatest(cipher_state$, running_state$, scan_progres$,
	  (cipher_state, running_state, progres) =>
      div('.decryption', {style: containerStyle}, [
		section({style: sectionStyle}, [
		  label({style: searchLabelStyle}, 'cipher:'),
		  input('.cipher', {type: 'text', style: inputTextStyle}),
		  button('.start_decrypt', {disabled: !cipher_state}, 'Start')
		])
		//,label({style: searchLabelStyle}, http_response)
		,
        ul({className: 'search-results'}, Object.keys(progres).map(result =>
          li({className: 'search-result'}, [
			label({style: searchLabelStyle}, result+':'+progres[result])
          ])
        )),
		h1(),
		//todoproper sorting needed
		Object.keys(progres).map(result =>
			label(hex2Message(string2hex(progres[result]))))
		
      ])
    );
  

  return {
    DOM: vtree$,
    HTTP: httpRequest$
  };
}

Cycle.run(main, {
  DOM: makeDOMDriver('#main-container'),
  HTTP: makeHTTPDriver()
});
