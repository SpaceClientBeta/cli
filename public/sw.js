self.addEventListener('notificationclick', event => {
  event.notification.close();
  event.waitUntil((async()=>{
    const clientsList=await clients.matchAll({type:'window',includeUncontrolled:true});
    for(const client of clientsList){
      if('focus' in client) return client.focus();
    }
    if(clients.openWindow) return clients.openWindow('/');
  })());
});
