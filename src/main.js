import Cycle from '@cycle/core';
import {div, button, h1, h4, a, makeDOMDriver} from '@cycle/dom';
import {makeHTTPDriver} from '@cycle/http';
import { Observable } from 'rx';

function main(sources) {
  const timer$ = Observable.timer(0, 5000)//.publish();
  const range$ = Observable.range(0, 3)
  //timer$.connect();


  const USERS_URL = 'http://crypto-class.appspot.com/po?';
  //const getRandomUser$ = timer$//sources.DOM.select('.get-random').events('click')
  const getRandomUser$ = sources.DOM.select('.get-random').events('click')
    .scan (seconds=>++seconds, 1)
    //.map(a => {return {url: USERS_URL + String(a), method: 'GET'};})

    //.selectMany (a => Rx.Observable.just(1).map(a => {return {url: USERS_URL + String(a), method: 'GET'};}));
    .selectMany (a => Observable.range(32, 128))
    .map(a => {return {url: USERS_URL + String(a), method: 'GET'};})
    
    
    
    


  const user$ = sources.HTTP
    .filter(res$ => res$.request.url.indexOf(USERS_URL) === 0)
    .mergeAll()
    .map(res => res.body)
    .startWith(null);

  const vtree$ = user$.map(user =>
      div('.users', [
      button('.get-random', 'Get random user'),
      user === null ? null : div('.user-details', [
        h1('.user-name', user.name),
        h4('.user-email', user.email),
        a('.user-website', {href: user.website}, user.website)
      ])
    ])
  );

  return {
    DOM: vtree$,
    HTTP: getRandomUser$
  };
}

Cycle.run(main, {
  DOM: makeDOMDriver('#main-container'),
  HTTP: makeHTTPDriver()
});
