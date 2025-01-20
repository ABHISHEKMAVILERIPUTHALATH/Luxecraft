// display value of the function

async function handlefunctionget(link){

    const loader = document.getElementById("loader");
    loader.style.display = 'block';

    try {
        const response = await axios.get(link);
        console.log("Response:", response);

        if (response.status === 200) {
            showToast(response.data, 'success');
        }
        else if(response.data ===201){

        }else if(response.status===204){
            showToast(response.data,'success')
        }
    } catch (error) {
        console.error('There was a problem with the request:', error);

        // Handle specific error codes
        if (error.response) {
            if (error.response.status === 400) {
                showToast(error.response.data, 'error');
            }else if (error.response.status === 401) {
                showToast(error.response.data, 'error');
            } else if (error.response.status === 404) {
                showToast(error.response.data, 'error');
            } else if(error.response.status ===500){
                showToast(error.response.data, 'error');
            }
        } else {
            console.log(error)
            showToast('Unable to connect to the server', 'error');
        }
    } finally {
        // Hide the loading spinner
        loader.style.display = 'none';
    }
}


//search implementation
async function search(item) {
    try {
        const shopElement=document.querySelector('#shop')
        shopElement.scrollIntoView({ behavior: 'smooth' });
        const searchResults = document.getElementById('product');
        searchResults.innerHTML = '<p>Loading...</p>'; // Show loading indicator

        const response = await axios.get(`http://localhost:3000/search?item=${encodeURIComponent(item)}`);
        const results = response.data;
        console.log(results)

        searchResults.innerHTML = ''; // Clear loading indicator

        if (results.length === 0) {
            searchResults.innerHTML = '<p>No results found.</p>';
            return;
        }

        results.forEach(result => {
            const resultDiv = document.createElement('div');
            resultDiv.className = 'product';
            const resultImg = result.img || '/path/to/default-image.jpg';
            resultDiv.innerHTML = `<div class="image-setup">
    <div>
        <img id="fullimage" src="${resultImg}" alt="Product Image">
    </div>
    <div class="overlay-icons">
        <span id="fullscreen" class="material-symbols-outlined" aria-label="Fullscreen" title="Fullscreen">open_in_full</span>
        <a onclick="favoritetoggle(${result.product_id})">
            <span
                data-id="${result.product_id}" 
                class="material-symbols-sharp favorite-icon" 
                aria-label="Add to Favorites" title="Add to Favorites">
                favorite
            </span>
        </a>
        <a onclick="cartadd(${result.product_id})">
            <span class="material-symbols-outlined" aria-label="Add to Cart" title="Add to Cart">shopping_bag</span>
        </a>
    </div>
</div>
<div class="info">
    <span class="Product-category">${result.itemname}</span>
    <span class="Product-name">${result.productname}</span>
    <span class="price">${result.price}</span>
    <span>${result.description}</span>
</div>`;
            searchResults.appendChild(resultDiv);
        });
    } catch (error) {
        console.error('Error fetching search results:', error);
        document.getElementById('search-results').innerHTML = '<p>Error loading results. Please try again later.</p>';
    }
}

//showing handled function
function showToast(message, type) {
    const toast = document.createElement('div');
    toast.classList.add('toast', type); 
    const icon = document.createElement('i');
    icon.classList.add('icon');
    if (type === 'success') {
        icon.classList.add('fas', 'fa-check-circle'); // Font Awesome check icon
    } else if (type === 'error') {
        icon.classList.add('fas', 'fa-times-circle'); // Font Awesome error (cross) icon
    } else if (type === 'warning') {
        icon.classList.add('fas', 'fa-exclamation-circle'); // Font Awesome warning icon
    }

    const messageText = document.createElement('span');
    messageText.textContent = message;
    
    toast.appendChild(icon);  
    toast.appendChild(messageText); 

    document.body.appendChild(toast);

    setTimeout(() => {
        toast.classList.add('show');
    }, 10); 
    setTimeout(() => {
        toast.classList.remove('show');
        setTimeout(() => {
            toast.remove();
        }, 300); 
    }, 3000);
}


//favorite button partial loading
async function favoritetoggle(id){
    try {
        const loader = document.getElementById("loader");
    loader.style.display = 'block';
        // Make the API request to toggle favorite status
        const response = await axios.get(`http://localhost:3000/toggle/${id}`);
        const favoriteIcon = document.querySelector(`[data-id="${id}"]`);
        // Ensure the request was successful
        if (response.status === 200) {
            // Update the UI based on the new favorite status
            if (response.data.value === "True") {
                favoriteIcon.style.color = 'Red';
            } else {
                favoriteIcon.style.color = 'Gray';
            }
        }
    } catch (error) {
        console.error('Error toggling favorite:', error);
        showToast(error.response.data,'error')
    } finally{
        loader.style.display='none'
    }
}