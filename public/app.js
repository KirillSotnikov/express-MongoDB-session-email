

const toCurrency = price => {
  return new Intl.NumberFormat('uk-UK', {
    currency: 'UAH',
    style: 'currency'
  }).format(price)
}

document.querySelectorAll('.price').forEach(item => {
  item.textContent = toCurrency(item.textContent)
})

const $card = document.getElementById('card')

if($card) {
  $card.addEventListener('click', event => {
    if(event.target.classList.contains('js-remove')) {
      const id = event.target.dataset.id
      const csrf = event.target.dataset.csrf
      
      fetch('/card/remove/' + id, {
        method: 'DELETE',
        headers: {
          'X-XSRF-TOKEN': csrf
        }
      }).then(res => res.json())
        .then(card => {
          if(card.courses.length){
            const html = card.courses.map(c => {
              return `
              <tr>
                <td>${c.name}</td>
                <td>${c.count}</td>
                <td>${c.price}</td>
                <td>
                  <button class="btn btn-small js-remove" data-id="${c._id}">Delete</button>
                </td>
              </tr>
              `
            }).join('')
            $card.querySelector('tbody').innerHTML = html
            $card.querySelector('.price').textContent = toCurrency(card.price)
          } else {
            $card.innerHTML ='<p>Card is empty</p>' 
          }
        })
    }
  })
}

const toDate = date => {
  return new Intl.DateTimeFormat('ru-RU', {
    day: '2-digit',
    month: 'long',
    year: 'numeric',
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit'
  }).format(new Date(date))
}


document.querySelectorAll('.date').forEach(item => {
  item.textContent = toDate(item.textContent)
})


var instance = M.Tabs.init(document.querySelectorAll('.tabs'));
