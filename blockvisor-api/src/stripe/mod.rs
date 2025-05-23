pub mod api;
mod client;

use std::sync::Arc;

use chrono::Datelike;
use displaydoc::Display;
use thiserror::Error;

use crate::auth::resource::{OrgId, UserId};
use crate::config::stripe::Config;
use crate::model::{Org, User};

use self::api::subscription::{QuantityModification, SubscriptionItem, SubscriptionItemId};
use self::api::{address, customer, invoice, payment_method, price, setup_intent, subscription};
use self::client::Client;

#[tonic::async_trait]
pub trait Payment {
    async fn create_setup_intent(
        &self,
        org_id: OrgId,
        user_id: UserId,
    ) -> Result<setup_intent::SetupIntent, Error>;

    async fn create_customer(
        &self,
        org: &Org,
        user: &User,
        payment_method_id: Option<&api::PaymentMethodId>,
    ) -> Result<customer::Customer, Error>;

    /// Attaches a payment method to a particular customer.
    async fn attach_payment_method(
        &self,
        payment_method_id: &api::PaymentMethodId,
        customer_id: &str,
    ) -> Result<payment_method::PaymentMethod, Error>;

    async fn list_payment_methods(
        &self,
        customer_id: &str,
    ) -> Result<Vec<payment_method::PaymentMethod>, Error>;

    async fn create_subscription(
        &self,
        customer_id: &str,
        price_id: &price::PriceId,
    ) -> Result<subscription::Subscription, Error>;

    async fn get_subscription(
        &self,
        subscription_id: &subscription::SubscriptionId,
    ) -> Result<subscription::Subscription, Error>;

    /// Each org only has one subscription.
    async fn get_subscription_by_customer(
        &self,
        customer_id: &str,
    ) -> Result<Option<subscription::Subscription>, Error>;

    async fn cancel_subscription(
        &self,
        subscription_id: &subscription::SubscriptionId,
    ) -> Result<(), Error>;

    async fn create_subscription_item(
        &self,
        subscription_id: &subscription::SubscriptionId,
        price_id: &price::PriceId,
    ) -> Result<subscription::SubscriptionItem, Error>;

    async fn get_subscription_item(
        &self,
        item_id: &subscription::SubscriptionItemId,
    ) -> Result<subscription::SubscriptionItem, Error>;

    /// Find a subscription item within a specific subscription, with the subscription identified by
    /// the subscription id, and the item within identified by the price_id.
    async fn find_subscription_item(
        &self,
        subscription_id: &subscription::SubscriptionId,
        price_id: &price::PriceId,
    ) -> Result<Option<subscription::SubscriptionItem>, Error>;

    async fn update_subscription_item(
        &self,
        item_id: &subscription::SubscriptionItemId,
        quantity: subscription::QuantityModification,
    ) -> Result<subscription::SubscriptionItem, Error>;

    async fn delete_subscription_item(
        &self,
        item_id: &subscription::SubscriptionItemId,
    ) -> Result<(), Error>;

    async fn get_price(&self, sku: &str) -> Result<price::Price, Error>;

    async fn get_address(
        &self,
        customer_id: &customer::CustomerId,
    ) -> Result<Option<address::Address>, Error>;

    async fn set_address(
        &self,
        customer_id: &str,
        address: &address::Address,
    ) -> Result<address::Address, Error>;

    async fn delete_address(&self, customer_id: &str) -> Result<(), Error>;

    async fn get_invoices(&self, customer_id: &str) -> Result<Vec<invoice::Invoice>, Error>;
}

#[tonic::async_trait]
pub trait Subscription: Payment {
    async fn add_subscription(&self, org: &Org, sku: &str) -> Result<SubscriptionItem, Error> {
        // If there is no corresponding record in stripe for this org, we cannot continue.
        let stripe_customer_id = org
            .stripe_customer_id
            .as_ref()
            .ok_or_else(|| Error::NoCustomer(org.id))?;

        let price = self.get_price(sku).await?;
        if let Some(subscription) = self
            .get_subscription_by_customer(stripe_customer_id)
            .await?
        {
            // If there is a subscription, we either need to increment the `quantity` of an existing
            // `item`, or we need to create a new item.
            if let Some(item) = self
                .find_subscription_item(&subscription.id, &price.id)
                .await?
            {
                // We found an item, so we will increase it's quantity by 1. Note that if no
                // quantity is set, that is equivalent to the quantity being 1.
                let new_quantity = QuantityModification::Increment {
                    current_quantity: item.quantity,
                };
                let item = self
                    .update_subscription_item(&item.id, new_quantity)
                    .await?;
                Ok(item)
            } else {
                // Since the subscription existed, but no item for the current `sku` already
                // existed, we create a new item within this subscription.
                let item = self
                    .create_subscription_item(&subscription.id, &price.id)
                    .await?;
                Ok(item)
            }
        } else {
            // There wasn't a subscription, so we create it and add the `item` for this node to it
            // straight away.
            let item = self
                .create_subscription(stripe_customer_id, &price.id)
                .await?
                .items
                .data
                .pop()
                .ok_or(Error::NoSubscriptionItem)?;
            Ok(item)
        }
    }

    async fn remove_subscription(&self, item_id: &SubscriptionItemId) -> Result<(), Error> {
        let item = self.get_subscription_item(item_id).await?;
        if item.quantity > 1 {
            let new_quantity = QuantityModification::Decrement {
                current_quantity: item.quantity,
            };
            self.update_subscription_item(item_id, new_quantity)
                .await
                .map(|_item| ())
        } else {
            let subscription_id = item.subscription.as_ref().ok_or(Error::NoSubscriptionId)?;
            let subscription = self.get_subscription(subscription_id).await?;
            match subscription.items.data.len() {
                // This item is in a subscription that doesn't have any items?
                0 => return Err(Error::ItemWithoutSubscription),
                // This is the final item of the subscription, lets cancel it
                1 => self.cancel_subscription(subscription_id).await,
                // There are other items left in this subscription, we can remove this item from
                // the subscription.
                _ => self.delete_subscription_item(item_id).await,
            }
        }
    }
}

#[derive(Debug, Display, Error)]
pub enum Error {
    /// Failed to create stripe Client: {0}
    AttachPaymentMethod(client::Error),
    /// Failed to cancel subscription: {0}
    CancelSubscription(client::Error),
    /// Error handling datetimes
    Chrono,
    /// Failed to create stripe Client: {0}
    CreateClient(client::Error),
    /// Failed to create stripe customer: {0}
    CreateCustomer(client::Error),
    /// Failed to create stripe setup intent: {0}
    CreateSetupIntent(client::Error),
    /// Failed to create stripe subscription: {0}
    CreateSubscription(client::Error),
    /// Failed to create stripe subscription item: {0}
    CreateSubscriptionItem(client::Error),
    /// Failed to delete address: {0}
    DeleteAddress(client::Error),
    /// Failed to delete stripe subscription item: {0}
    DeleteSubscriptionItem(client::Error),
    /// Failed to find subscription items: {0}
    FindSubscriptionItems(client::Error),
    /// Failed to get address: {0}
    GetAddress(client::Error),
    /// Failed to get invoices: {0}
    GetInvoices(client::Error),
    /// Failed to get subscription: {0}
    GetSubscription(client::Error),
    /// Failed to get subscription item: {0}
    GetSubscriptionItem(client::Error),
    /// Found a stripe item that isn't in any extant subscription.
    ItemWithoutSubscription,
    /// Failed to list stripe payment methods: {0}
    ListPaymentMethods(client::Error),
    /// Failed to list stripe subscriptions: {0}
    ListSubscriptions(client::Error),
    /// No address found for the current customer.
    NoAddress,
    /// Org with id `{0}` has no customer in stripe.
    NoCustomer(OrgId),
    /// No price found on stripe for sku `{0}`.
    NoPrice(String),
    /// Stripe responded with a susbcription item that has no subscription id set.
    NoSubscriptionId,
    /// Can't cancel a subscription for an org that doesn't have one.
    NoSubscriptionToCancel,
    /// Newly created subscription has no items.
    NoSubscriptionItem,
    /// Failed to search stripe prices: {0}
    SearchPrices(client::Error),
    /// Failed to set address: {0}
    SetAddress(client::Error),
    /// Failed to update subscription item: {0}
    UpdateSubscriptionItem(client::Error),
}

pub struct Stripe {
    pub config: Arc<Config>,
    pub client: Client,
}

impl Stripe {
    pub fn new(config: Arc<Config>) -> Result<Option<Self>, Error> {
        let Some(secret) = config.secret.as_ref() else {
            return Ok(None);
        };
        let client = Client::new(secret, &config.base_url).map_err(Error::CreateClient)?;
        Ok(Some(Stripe { config, client }))
    }

    #[cfg(any(test, feature = "integration-test"))]
    pub fn new_mock(config: Arc<Config>, server_url: url::Url) -> Result<Self, Error> {
        let client = Client::new_mock(server_url).map_err(Error::CreateClient)?;
        Ok(Self { config, client })
    }
}

#[tonic::async_trait]
impl Subscription for Stripe {}

#[tonic::async_trait]
impl Payment for Stripe {
    async fn create_setup_intent(
        &self,
        org_id: OrgId,
        user_id: UserId,
    ) -> Result<setup_intent::SetupIntent, Error> {
        let req = setup_intent::CreateSetupIntent::new(org_id, user_id);
        self.client
            .request(&req)
            .await
            .map_err(Error::CreateSetupIntent)
    }

    async fn create_customer(
        &self,
        org: &Org,
        user: &User,
        payment_method_id: Option<&api::PaymentMethodId>,
    ) -> Result<customer::Customer, Error> {
        let customer = customer::CreateCustomer::new(org, user, payment_method_id);
        self.client
            .request(&customer)
            .await
            .map_err(Error::CreateCustomer)
    }

    async fn attach_payment_method(
        &self,
        payment_method_id: &api::PaymentMethodId,
        customer_id: &str,
    ) -> Result<payment_method::PaymentMethod, Error> {
        let attach = payment_method::AttachPaymentMethod::new(payment_method_id, customer_id);
        self.client
            .request(&attach)
            .await
            .map_err(Error::AttachPaymentMethod)
    }

    async fn list_payment_methods(
        &self,
        customer_id: &str,
    ) -> Result<Vec<payment_method::PaymentMethod>, Error> {
        let req = payment_method::ListPaymentMethodsRequest::new(customer_id);
        let resp = self
            .client
            .request(&req)
            .await
            .map_err(Error::ListPaymentMethods)?;
        Ok(resp.data)
    }

    async fn create_subscription(
        &self,
        customer_id: &str,
        price_id: &price::PriceId,
    ) -> Result<subscription::Subscription, Error> {
        // We send our invoices at 04:00 GMT on the first of the month.
        let first_invoice = chrono::Utc::now()
            .date_naive()
            .with_day(1)
            .ok_or(Error::Chrono)?
            .and_hms_opt(4, 0, 0)
            .ok_or(Error::Chrono)?
            .checked_add_months(chrono::Months::new(1))
            .ok_or(Error::Chrono)?
            .and_utc();
        let req = subscription::CreateSubscription::new(customer_id, price_id, first_invoice);
        self.client
            .request(&req)
            .await
            .map_err(Error::CreateSubscription)
    }

    async fn get_subscription(
        &self,
        subscription_id: &subscription::SubscriptionId,
    ) -> Result<subscription::Subscription, Error> {
        let req = subscription::GetSubscription::new(subscription_id);
        self.client
            .request(&req)
            .await
            .map_err(Error::GetSubscription)
    }

    async fn get_subscription_by_customer(
        &self,
        customer_id: &str,
    ) -> Result<Option<subscription::Subscription>, Error> {
        let req = subscription::ListSubscriptions::new(customer_id);
        let mut subscriptions = self
            .client
            .request(&req)
            .await
            .map_err(Error::ListSubscriptions)?
            .data;
        if let Some(subscription) = subscriptions.pop() {
            if !subscriptions.is_empty() {
                tracing::warn!("More than one subscription returned for customer `{customer_id}`.");
            }
            Ok(Some(subscription))
        } else {
            Ok(None)
        }
    }

    async fn cancel_subscription(
        &self,
        subscription_id: &subscription::SubscriptionId,
    ) -> Result<(), Error> {
        let req = subscription::CancelSubscriptionRequest::new(subscription_id);
        self.client
            .request(&req)
            .await
            .map_err(Error::CancelSubscription)?;
        Ok(())
    }

    async fn create_subscription_item(
        &self,
        subscription_id: &subscription::SubscriptionId,
        price_id: &price::PriceId,
    ) -> Result<subscription::SubscriptionItem, Error> {
        let req = subscription::CreateSubscriptionItem::new(subscription_id, price_id);
        self.client
            .request(&req)
            .await
            .map_err(Error::CreateSubscriptionItem)
    }

    async fn get_subscription_item(
        &self,
        item_id: &subscription::SubscriptionItemId,
    ) -> Result<subscription::SubscriptionItem, Error> {
        let req = subscription::GetSubscriptionItem::new(item_id);
        self.client
            .request(&req)
            .await
            .map_err(Error::GetSubscriptionItem)
    }

    async fn find_subscription_item(
        &self,
        subscription_id: &subscription::SubscriptionId,
        price_id: &price::PriceId,
    ) -> Result<Option<subscription::SubscriptionItem>, Error> {
        let req = subscription::ListSubscriptionItems::new(subscription_id);
        let items = self
            .client
            .request(&req)
            .await
            .map_err(Error::FindSubscriptionItems)?;
        // TODO: this is silly, find a better way
        Ok(items
            .data
            .into_iter()
            .find(|item| item.price.as_ref().map(|price| &price.id) == Some(price_id)))
    }

    async fn update_subscription_item(
        &self,
        item_id: &subscription::SubscriptionItemId,
        quantity: subscription::QuantityModification,
    ) -> Result<subscription::SubscriptionItem, Error> {
        let req = subscription::UpdateSubscriptionItem::new(item_id, quantity);
        self.client
            .request(&req)
            .await
            .map_err(Error::UpdateSubscriptionItem)
    }

    async fn delete_subscription_item(
        &self,
        item_id: &subscription::SubscriptionItemId,
    ) -> Result<(), Error> {
        let req = subscription::DeleteSubscriptionItem::new(item_id);
        self.client
            .request(&req)
            .await
            .map_err(Error::DeleteSubscriptionItem)?;
        Ok(())
    }

    async fn get_price(&self, sku: &str) -> Result<price::Price, Error> {
        let req = price::SearchPrice::new(sku);
        let mut prices = self
            .client
            .request(&req)
            .await
            .map_err(Error::SearchPrices)?
            .data;
        if let Some(price) = prices.pop() {
            if !prices.is_empty() {
                tracing::warn!("More than one price returned for sku `{sku}`.");
            }
            Ok(price)
        } else {
            tracing::error!("No price returned for sku `{sku}`.");
            Err(Error::NoPrice(sku.to_string()))
        }
    }

    async fn get_address(
        &self,
        customer_id: &customer::CustomerId,
    ) -> Result<Option<address::Address>, Error> {
        let req = customer::GetCustomer::new(customer_id);
        let customer = self.client.request(&req).await.map_err(Error::GetAddress)?;
        Ok(customer.address)
    }

    async fn set_address(
        &self,
        customer_id: &str,
        address: &address::Address,
    ) -> Result<address::Address, Error> {
        let req = customer::UpdateCustomer::new(
            customer_id,
            address.city.as_deref(),
            address.country.as_deref(),
            address.line1.as_deref(),
            address.line2.as_deref(),
            address.postal_code.as_deref(),
            address.state.as_deref(),
        );
        let customer = self.client.request(&req).await.map_err(Error::SetAddress)?;
        customer.address.ok_or(Error::NoAddress)
    }

    async fn delete_address(&self, customer_id: &str) -> Result<(), Error> {
        let req = customer::UpdateCustomer::new(customer_id, None, None, None, None, None, None);
        let customer = self
            .client
            .request(&req)
            .await
            .map_err(Error::DeleteAddress)?;
        if customer
            .address
            .as_ref()
            .and_then(|add| add.line1.as_deref())
            .is_some()
        {
            tracing::warn!("Address is still in place afer a delete: {customer:?}");
        }
        Ok(())
    }

    async fn get_invoices(&self, customer_id: &str) -> Result<Vec<invoice::Invoice>, Error> {
        let req = invoice::ListInvoices::new(customer_id, true);
        let resp = self
            .client
            .request(&req)
            .await
            .map_err(Error::GetInvoices)?;
        Ok(resp.data)
    }
}

#[cfg(any(test, feature = "integration-test"))]
pub mod tests {
    use mockito::{Matcher, ServerGuard};

    use super::*;

    pub struct MockStripe {
        pub server: ServerGuard,
        pub stripe: Stripe,
    }

    #[tonic::async_trait]
    impl Subscription for MockStripe {}

    #[tonic::async_trait]
    impl Payment for MockStripe {
        async fn create_setup_intent(
            &self,
            org_id: OrgId,
            user_id: UserId,
        ) -> Result<setup_intent::SetupIntent, Error> {
            self.stripe.create_setup_intent(org_id, user_id).await
        }

        async fn create_customer(
            &self,
            org: &Org,
            user: &User,
            payment_method_id: Option<&api::PaymentMethodId>,
        ) -> Result<customer::Customer, Error> {
            self.stripe
                .create_customer(org, user, payment_method_id)
                .await
        }

        async fn attach_payment_method(
            &self,
            payment_method_id: &api::PaymentMethodId,
            customer_id: &str,
        ) -> Result<payment_method::PaymentMethod, Error> {
            self.stripe
                .attach_payment_method(payment_method_id, customer_id)
                .await
        }

        async fn list_payment_methods(
            &self,
            customer_id: &str,
        ) -> Result<Vec<payment_method::PaymentMethod>, Error> {
            self.stripe.list_payment_methods(customer_id).await
        }

        async fn create_subscription(
            &self,
            customer_id: &str,
            price_id: &price::PriceId,
        ) -> Result<subscription::Subscription, Error> {
            self.stripe.create_subscription(customer_id, price_id).await
        }

        async fn get_subscription(
            &self,
            subscription_id: &subscription::SubscriptionId,
        ) -> Result<subscription::Subscription, Error> {
            self.stripe.get_subscription(subscription_id).await
        }

        /// Each org only has one subscription.
        async fn get_subscription_by_customer(
            &self,
            customer_id: &str,
        ) -> Result<Option<subscription::Subscription>, Error> {
            self.stripe.get_subscription_by_customer(customer_id).await
        }

        async fn cancel_subscription(
            &self,
            subscription_id: &subscription::SubscriptionId,
        ) -> Result<(), Error> {
            self.stripe.cancel_subscription(subscription_id).await
        }

        async fn create_subscription_item(
            &self,
            subscription_id: &subscription::SubscriptionId,
            price_id: &price::PriceId,
        ) -> Result<subscription::SubscriptionItem, Error> {
            self.stripe
                .create_subscription_item(subscription_id, price_id)
                .await
        }

        async fn get_subscription_item(
            &self,
            item_id: &subscription::SubscriptionItemId,
        ) -> Result<subscription::SubscriptionItem, Error> {
            self.stripe.get_subscription_item(item_id).await
        }

        async fn find_subscription_item(
            &self,
            subscription_id: &subscription::SubscriptionId,
            price_id: &price::PriceId,
        ) -> Result<Option<subscription::SubscriptionItem>, Error> {
            self.stripe
                .find_subscription_item(subscription_id, price_id)
                .await
        }

        async fn update_subscription_item(
            &self,
            item_id: &subscription::SubscriptionItemId,
            quantity: subscription::QuantityModification,
        ) -> Result<subscription::SubscriptionItem, Error> {
            self.stripe
                .update_subscription_item(item_id, quantity)
                .await
        }

        async fn delete_subscription_item(
            &self,
            item_id: &subscription::SubscriptionItemId,
        ) -> Result<(), Error> {
            self.stripe.delete_subscription_item(item_id).await
        }

        async fn get_price(&self, sku: &str) -> Result<price::Price, Error> {
            self.stripe.get_price(sku).await
        }

        async fn get_address(
            &self,
            customer_id: &customer::CustomerId,
        ) -> Result<Option<address::Address>, Error> {
            self.stripe.get_address(customer_id).await
        }

        async fn set_address(
            &self,
            customer_id: &str,
            address: &address::Address,
        ) -> Result<address::Address, Error> {
            self.stripe.set_address(customer_id, address).await
        }

        async fn delete_address(&self, customer_id: &str) -> Result<(), Error> {
            self.stripe.delete_address(customer_id).await
        }

        async fn get_invoices(&self, customer_id: &str) -> Result<Vec<invoice::Invoice>, Error> {
            self.stripe.get_invoices(customer_id).await
        }
    }

    impl MockStripe {
        pub async fn new() -> Self {
            let server = mock_server().await;
            let server_url = format!("{}/v1/", server.url()).parse().unwrap();
            let config = Arc::new(mock_config(&server));
            let stripe = Stripe::new_mock(config, server_url).unwrap();

            Self { server, stripe }
        }
    }

    async fn mock_server() -> ServerGuard {
        let mut server = mockito::Server::new_async().await;

        server
            .mock("POST", "/v1/setup_intents")
            .with_status(200)
            .with_body(mock_setup_intent())
            .create_async()
            .await;

        server
            .mock("POST", "/v1/customers")
            .with_status(201)
            .with_body(mock_customer())
            .create_async()
            .await;

        server
            .mock("POST", "/v1/payment_methods/moneyfaucet/attach")
            .with_status(201)
            .with_body(mock_payment_method())
            .create_async()
            .await;

        server
            .mock("GET", "/v1/payment_methods?customer=cus_NffrFeUfNV2Hib")
            .with_status(200)
            .with_body(mock_payment_methods())
            .create_async()
            .await;

        server
            .mock("POST", "/v1/subscriptions")
            .with_status(201)
            .with_body(mock_subscription())
            .create_async()
            .await;

        server
            .mock("POST", "/v1/subscription_items")
            .with_status(201)
            .with_body(mock_subscription_item())
            .create_async()
            .await;

        server
            .mock("GET", Matcher::Regex("^/v1/subscriptions".into()))
            .with_status(200)
            .with_body(mock_subscriptions())
            .create_async()
            .await;

        server
            .mock(
                "GET",
                Matcher::Regex("^/v1/subscription_items/si_NcLYdDxLHxlFo7".into()),
            )
            .with_status(200)
            .with_body(mock_subscription_item())
            .create_async()
            .await;

        server
            .mock(
                "POST",
                Matcher::Regex("^/v1/subscription_items/si_NcLYdDxLHxlFo7".into()),
            )
            .with_status(200)
            .with_body(mock_subscription_item())
            .create_async()
            .await;

        server
            .mock("GET", Matcher::Regex("^/v1/subscription_items".into()))
            .with_status(200)
            .with_body(mock_subscription_items())
            .create_async()
            .await;

        server
            .mock("GET", Matcher::Regex(r"^/v1/prices/search".into()))
            .with_status(200)
            .with_body(mock_prices())
            .create_async()
            .await;

        server
    }

    fn mock_config(server: &ServerGuard) -> Config {
        Config {
            secret: Some("stripe_fake_secret".to_owned().into()),
            base_url: format!("{}/v1/", server.url()),
        }
    }

    const fn mock_setup_intent() -> &'static str {
        r#"{
          "id": "seti_1PIt1LB5ce1jJsfThXFVl6TA",
          "object": "setup_intent",
          "application": null,
          "automatic_payment_methods": null,
          "cancellation_reason": null,
          "client_secret": "seti_1PIt1LB5ce1jJsfThXFVl6TA_secret_Q9BOXjYJe26wDp1MJs4Yx6va95vOSJv",
          "created": 1716299187,
          "customer": null,
          "description": null,
          "flow_directions": null,
          "last_setup_error": null,
          "latest_attempt": null,
          "livemode": false,
          "mandate": null,
          "metadata": {},
          "next_action": null,
          "on_behalf_of": null,
          "payment_method": "moneyfaucet",
          "payment_method_configuration_details": null,
          "payment_method_options": {
            "card": {
              "mandate_options": null,
              "network": null,
              "request_three_d_secure": "automatic"
            }
          },
          "payment_method_types": [
            "card"
          ],
          "single_use_mandate": null,
          "status": "requires_payment_method",
          "usage": "off_session"
        }"#
    }

    const fn mock_customer() -> &'static str {
        r#"{
          "id": "cus_NffrFeUfNV2Hib",
          "object": "customer",
          "address": null,
          "balance": 0,
          "created": 1680893993,
          "currency": null,
          "default_source": null,
          "delinquent": false,
          "description": null,
          "discount": null,
          "email": "jennyrosen@example.com",
          "invoice_prefix": "0759376C",
          "invoice_settings": {
            "custom_fields": null,
            "default_payment_method": null,
            "footer": null,
            "rendering_options": null
          },
          "livemode": false,
          "metadata": {},
          "name": "Jenny Rosen",
          "next_invoice_sequence": 1,
          "phone": null,
          "preferred_locales": [],
          "shipping": null,
          "tax_exempt": "none",
          "test_clock": null
        }"#
    }

    const fn mock_prices() -> &'static str {
        r#"{
          "object": "search_result",
          "url": "/v1/prices/search",
          "has_more": false,
          "data": [
            {
              "id": "price_1MoBy5LkdIwHu7ixZhnattbh",
              "object": "price",
              "active": true,
              "billing_scheme": "per_unit",
              "created": 1679431181,
              "currency": "usd",
              "custom_unit_amount": null,
              "livemode": false,
              "lookup_key": null,
              "metadata": {
                "order_id": "6735"
              },
              "nickname": null,
              "product": "prod_NZKdYqrwEYx6iK",
              "recurring": {
                "aggregate_usage": null,
                "interval": "month",
                "interval_count": 1,
                "trial_period_days": null,
                "usage_type": "licensed"
              },
              "tax_behavior": "unspecified",
              "tiers_mode": null,
              "transform_quantity": null,
              "type": "recurring",
              "unit_amount": 1000,
              "unit_amount_decimal": "1000"
            }
          ]
        }"#
    }

    const fn mock_payment_method() -> &'static str {
        r#"{
          "id": "pm_1MqM05LkdIwHu7ixlDxxO6Mc",
          "object": "payment_method",
          "billing_details": {
            "address": {
              "city": null,
              "country": null,
              "line1": null,
              "line2": null,
              "postal_code": null,
              "state": null
            },
            "email": null,
            "name": null,
            "phone": null
          },
          "card": {
            "brand": "visa",
            "checks": {
              "address_line1_check": null,
              "address_postal_code_check": null,
              "cvc_check": "pass"
            },
            "country": "US",
            "exp_month": 8,
            "exp_year": 2026,
            "fingerprint": "mToisGZ01V71BCos",
            "funding": "credit",
            "generated_from": null,
            "last4": "4242",
            "networks": {
              "available": [
                "visa"
              ],
              "preferred": null
            },
            "three_d_secure_usage": {
              "supported": true
            },
            "wallet": null
          },
          "created": 1679946402,
          "customer": "cus_NffrFeUfNV2Hib",
          "livemode": false,
          "metadata": {},
          "type": "card"
        }"#
    }

    const fn mock_payment_methods() -> &'static str {
        r#"{
          "object": "list",
          "url": "/v1/customers/cus_NffrFeUfNV2Hib/payment_methods",
          "has_more": false,
          "data": [
            {
              "id": "pm_1MqM05LkdIwHu7ixlDxxO6Mc",
              "object": "payment_method",
              "billing_details": {
                "address": {
                  "city": null,
                  "country": null,
                  "line1": null,
                  "line2": null,
                  "postal_code": null,
                  "state": null
                },
                "email": null,
                "name": null,
                "phone": null
              },
              "card": {
                "brand": "visa",
                "checks": {
                  "address_line1_check": null,
                  "address_postal_code_check": null,
                  "cvc_check": "pass"
                },
                "country": "US",
                "exp_month": 8,
                "exp_year": 2026,
                "fingerprint": "mToisGZ01V71BCos",
                "funding": "credit",
                "generated_from": null,
                "last4": "4242",
                "networks": {
                  "available": [
                    "visa"
                  ],
                  "preferred": null
                },
                "three_d_secure_usage": {
                  "supported": true
                },
                "wallet": null
              },
              "created": 1679946402,
              "customer": "cus_NffrFeUfNV2Hib",
              "livemode": false,
              "metadata": {},
              "type": "card"
            }
          ]
        }"#
    }

    const fn mock_subscription() -> &'static str {
        r#"{
          "id": "sub_1MowQVLkdIwHu7ixeRlqHVzs",
          "object": "subscription",
          "application": null,
          "application_fee_percent": null,
          "automatic_tax": {
            "enabled": false,
            "liability": null
          },
          "billing_cycle_anchor": 1679609767,
          "billing_thresholds": null,
          "cancel_at": null,
          "cancel_at_period_end": false,
          "canceled_at": null,
          "cancellation_details": {
            "comment": null,
            "feedback": null,
            "reason": null
          },
          "collection_method": "charge_automatically",
          "created": 1679609767,
          "currency": "usd",
          "current_period_end": 1682288167,
          "current_period_start": 1679609767,
          "customer": "cus_NffrFeUfNV2Hib",
          "days_until_due": null,
          "default_payment_method": null,
          "default_source": null,
          "default_tax_rates": [],
          "description": null,
          "discount": null,
          "discounts": null,
          "ended_at": null,
          "invoice_settings": {
            "issuer": {
              "type": "self"
            }
          },
          "items": {
            "object": "list",
            "data": [
              {
                "id": "si_Na6dzxczY5fwHx",
                "object": "subscription_item",
                "billing_thresholds": null,
                "created": 1679609768,
                "metadata": {},
                "plan": {
                  "id": "price_1MowQULkdIwHu7ixraBm864M",
                  "object": "plan",
                  "active": true,
                  "aggregate_usage": null,
                  "amount": 1000,
                  "amount_decimal": "1000",
                  "billing_scheme": "per_unit",
                  "created": 1679609766,
                  "currency": "usd",
                  "discounts": null,
                  "interval": "month",
                  "interval_count": 1,
                  "livemode": false,
                  "metadata": {},
                  "nickname": null,
                  "product": "prod_Na6dGcTsmU0I4R",
                  "tiers_mode": null,
                  "transform_usage": null,
                  "trial_period_days": null,
                  "usage_type": "licensed"
                },
                "price": {
                  "id": "price_1MowQULkdIwHu7ixraBm864M",
                  "object": "price",
                  "active": true,
                  "billing_scheme": "per_unit",
                  "created": 1679609766,
                  "currency": "usd",
                  "custom_unit_amount": null,
                  "livemode": false,
                  "lookup_key": null,
                  "metadata": {},
                  "nickname": null,
                  "product": "prod_Na6dGcTsmU0I4R",
                  "recurring": {
                    "aggregate_usage": null,
                    "interval": "month",
                    "interval_count": 1,
                    "trial_period_days": null,
                    "usage_type": "licensed"
                  },
                  "tax_behavior": "unspecified",
                  "tiers_mode": null,
                  "transform_quantity": null,
                  "type": "recurring",
                  "unit_amount": 1000,
                  "unit_amount_decimal": "1000"
                },
                "quantity": 1,
                "subscription": "sub_1MowQVLkdIwHu7ixeRlqHVzs",
                "tax_rates": []
              }
            ],
            "has_more": false,
            "total_count": 1,
            "url": "/v1/subscription_items?subscription=sub_1MowQVLkdIwHu7ixeRlqHVzs"
          },
          "latest_invoice": "in_1MowQWLkdIwHu7ixuzkSPfKd",
          "livemode": false,
          "metadata": {},
          "next_pending_invoice_item_invoice": null,
          "on_behalf_of": null,
          "pause_collection": null,
          "payment_settings": {
            "payment_method_options": null,
            "payment_method_types": null,
            "save_default_payment_method": "off"
          },
          "pending_invoice_item_interval": null,
          "pending_setup_intent": null,
          "pending_update": null,
          "schedule": null,
          "start_date": 1679609767,
          "status": "active",
          "test_clock": null,
          "transfer_data": null,
          "trial_end": null,
          "trial_settings": {
            "end_behavior": {
              "missing_payment_method": "create_invoice"
            }
          },
          "trial_start": null
        }"#
    }

    const fn mock_subscription_item() -> &'static str {
        r#"{
          "id": "si_NcLYdDxLHxlFo7",
          "object": "subscription_item",
          "billing_thresholds": null,
          "created": 1680126546,
          "metadata": {},
          "price": {
            "id": "price_1Mr6rdLkdIwHu7ixwPmiybbR",
            "object": "price",
            "active": true,
            "billing_scheme": "per_unit",
            "created": 1680126545,
            "currency": "usd",
            "custom_unit_amount": null,
            "discounts": null,
            "livemode": false,
            "lookup_key": null,
            "metadata": {},
            "nickname": null,
            "product": "prod_NcLYGKH0eY5b8s",
            "recurring": {
              "aggregate_usage": null,
              "interval": "month",
              "interval_count": 1,
              "trial_period_days": null,
              "usage_type": "licensed"
            },
            "tax_behavior": "unspecified",
            "tiers_mode": null,
            "transform_quantity": null,
            "type": "recurring",
            "unit_amount": 1000,
            "unit_amount_decimal": "1000"
          },
          "quantity": 2,
          "subscription": "sub_1Mr6rbLkdIwHu7ix4Xm9Ahtd",
          "tax_rates": []
        }"#
    }

    const fn mock_subscriptions() -> &'static str {
        r#"{
          "object": "list",
          "url": "/v1/subscriptions",
          "has_more": false,
          "data": [
            {
              "id": "sub_1MowQVLkdIwHu7ixeRlqHVzs",
              "object": "subscription",
              "application": null,
              "application_fee_percent": null,
              "automatic_tax": {
                "enabled": false,
                "liability": null
              },
              "billing_cycle_anchor": 1679609767,
              "billing_thresholds": null,
              "cancel_at": null,
              "cancel_at_period_end": false,
              "canceled_at": null,
              "cancellation_details": {
                "comment": null,
                "feedback": null,
                "reason": null
              },
              "collection_method": "charge_automatically",
              "created": 1679609767,
              "currency": "usd",
              "current_period_end": 1682288167,
              "current_period_start": 1679609767,
              "customer": "cus_NffrFeUfNV2Hib",
              "days_until_due": null,
              "default_payment_method": null,
              "default_source": null,
              "default_tax_rates": [],
              "description": null,
              "discount": null,
              "discounts": null,
              "ended_at": null,
              "invoice_settings": {
                "issuer": {
                  "type": "self"
                }
              },
              "items": {
                "object": "list",
                "data": [
                  {
                    "id": "si_Na6dzxczY5fwHx",
                    "object": "subscription_item",
                    "billing_thresholds": null,
                    "created": 1679609768,
                    "metadata": {},
                    "plan": {
                      "id": "price_1MowQULkdIwHu7ixraBm864M",
                      "object": "plan",
                      "active": true,
                      "aggregate_usage": null,
                      "amount": 1000,
                      "amount_decimal": "1000",
                      "billing_scheme": "per_unit",
                      "created": 1679609766,
                      "currency": "usd",
                      "discounts": null,
                      "interval": "month",
                      "interval_count": 1,
                      "livemode": false,
                      "metadata": {},
                      "nickname": null,
                      "product": "prod_Na6dGcTsmU0I4R",
                      "tiers_mode": null,
                      "transform_usage": null,
                      "trial_period_days": null,
                      "usage_type": "licensed"
                    },
                    "price": {
                      "id": "price_1MowQULkdIwHu7ixraBm864M",
                      "object": "price",
                      "active": true,
                      "billing_scheme": "per_unit",
                      "created": 1679609766,
                      "currency": "usd",
                      "custom_unit_amount": null,
                      "livemode": false,
                      "lookup_key": null,
                      "metadata": {},
                      "nickname": null,
                      "product": "prod_Na6dGcTsmU0I4R",
                      "recurring": {
                        "aggregate_usage": null,
                        "interval": "month",
                        "interval_count": 1,
                        "trial_period_days": null,
                        "usage_type": "licensed"
                      },
                      "tax_behavior": "unspecified",
                      "tiers_mode": null,
                      "transform_quantity": null,
                      "type": "recurring",
                      "unit_amount": 1000,
                      "unit_amount_decimal": "1000"
                    },
                    "quantity": 1,
                    "subscription": "sub_1MowQVLkdIwHu7ixeRlqHVzs",
                    "tax_rates": []
                  }
                ],
                "has_more": false,
                "total_count": 1,
                "url": "/v1/subscription_items?subscription=sub_1MowQVLkdIwHu7ixeRlqHVzs"
              },
              "latest_invoice": "in_1MowQWLkdIwHu7ixuzkSPfKd",
              "livemode": false,
              "metadata": {},
              "next_pending_invoice_item_invoice": null,
              "on_behalf_of": null,
              "pause_collection": null,
              "payment_settings": {
                "payment_method_options": null,
                "payment_method_types": null,
                "save_default_payment_method": "off"
              },
              "pending_invoice_item_interval": null,
              "pending_setup_intent": null,
              "pending_update": null,
              "schedule": null,
              "start_date": 1679609767,
              "status": "active",
              "test_clock": null,
              "transfer_data": null,
              "trial_end": null,
              "trial_settings": {
                "end_behavior": {
                  "missing_payment_method": "create_invoice"
                }
              },
              "trial_start": null
            }
          ]
        }"#
    }

    const fn mock_subscription_items() -> &'static str {
        r#"{
          "object": "list",
          "url": "/v1/subscription_items",
          "has_more": false,
          "data": [
            {
              "id": "si_OCgWsGlqpbN4EP",
              "object": "subscription_item",
              "billing_thresholds": null,
              "created": 1688507587,
              "metadata": {},
              "price": {
                "id": "price_1NQH9iLkdIwHu7ix3tkaSxhj",
                "object": "price",
                "active": true,
                "billing_scheme": "per_unit",
                "created": 1688507586,
                "currency": "usd",
                "custom_unit_amount": null,
                "livemode": false,
                "lookup_key": null,
                "metadata": {},
                "nickname": null,
                "product": "prod_OCgWE6cbwiSu27",
                "recurring": {
                  "aggregate_usage": null,
                  "interval": "month",
                  "interval_count": 1,
                  "trial_period_days": null,
                  "usage_type": "licensed"
                },
                "tax_behavior": "unspecified",
                "tiers_mode": null,
                "transform_quantity": null,
                "type": "recurring",
                "unit_amount": 1000,
                "unit_amount_decimal": "1000"
              },
              "quantity": 1,
              "subscription": "sub_1NQH9iLkdIwHu7ixxhHui9yi",
              "tax_rates": []
            }
          ]
        }"#
    }
}
